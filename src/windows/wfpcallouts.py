# This file is Copyright 2026 chizzydev and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
"""Windows Filtering Platform runtime callout reconstruction.

Validated architecture:
  * NETIO!FeGetWfpGlobalPtr is resolved from the in-memory export directory.
  * gWfpGlobal is recovered from the export's RIP-relative code path.
  * The callout capacity/table pair is discovered structurally from gWfpGlobal;
    their offsets are not hardcoded.
  * The validated Windows 11 26H2 entry layout is 0x60 bytes.
  * Current-build evidence identifies:
        +0x10 classify callback
        +0x18 notify callback
        +0x20 optional flow-delete callback
    +0x28 is retained as a version-specific auxiliary callback slot.
  * Kernel-enabled entries are indexed by the WFP runtime CalloutId.
  * FWPM management-object presence is a distinct lifecycle and is not
    assumed to equal kernel FWPS registration state.

The plugin intentionally contains no fixture-specific callout IDs, GUIDs, names, or
truth values.  Unsupported layouts fail closed instead of guessing.
"""

import json
import logging
import struct

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class WfpCallouts(interfaces.plugins.PluginInterface):
    """Reconstructs kernel-enabled WFP callouts and their callback ownership."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    ENTRY_STRIDE = 0x60

    CALLOUT_TYPE_OFFSET = 0x00
    ENABLED_OFFSET = 0x04
    CLASSIFY_OFFSET = 0x10
    NOTIFY_OFFSET = 0x18
    FLOW_DELETE_OFFSET = 0x20
    AUX_CALLBACK_OFFSET = 0x28
    FLAGS_OFFSET = 0x30
    DEVICE_OBJECT_OFFSET = 0x40
    LAYER_INFO_OFFSET = 0x4C
    TFO_INCOMPAT_OFFSET = 0x4E

    GLOBAL_SCAN_BYTES = 0x400
    MIN_CAPACITY = 64
    MAX_CAPACITY = 16384
    MAX_ENUM_CAPACITY = 16384

    @staticmethod
    def _modules():
        from volatility3.plugins.windows import modules
        return modules

    @classmethod
    def get_requirements(cls):
        modules = cls._modules()
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="modules",
                component=modules.Modules,
                version=(3, 0, 0),
            ),
            requirements.ListRequirement(
                name="callout-id",
                element_type=int,
                description="Callout ID(s) to include",
                optional=True,
            ),
            requirements.ListRequirement(
                name="module",
                element_type=str,
                description=(
                    "Callback owner module(s) to include, for example tcpip.sys "
                    "or mpsdrv.sys"
                ),
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-inactive",
                description=(
                    "Include kernel-disabled table entries. These are implementation-state "
                    "rows and are not registered/enabled WFP kernel callouts."
                ),
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def _norm(layer, value):
        return int(value) & int(layer.address_mask)

    @classmethod
    def _read(cls, layer, address, size):
        if not address or size <= 0:
            return b""
        try:
            return layer.read(cls._norm(layer, address), size, pad=False)
        except (exceptions.InvalidAddressException, ValueError, TypeError):
            return b""

    @classmethod
    def _u8(cls, layer, address):
        data = cls._read(layer, address, 1)
        return data[0] if len(data) == 1 else None

    @classmethod
    def _u16(cls, layer, address):
        data = cls._read(layer, address, 2)
        return struct.unpack("<H", data)[0] if len(data) == 2 else None

    @classmethod
    def _u32(cls, layer, address):
        data = cls._read(layer, address, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else None

    @classmethod
    def _u64(cls, layer, address):
        data = cls._read(layer, address, 8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else None

    @classmethod
    def _cstring(cls, layer, address, limit=256):
        data = cls._read(layer, address, limit)
        if not data:
            return ""
        return data.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    @classmethod
    def _pe_exports(cls, layer, base):
        """Parses an in-memory PE export directory without external libraries."""
        if cls._u16(layer, base) != 0x5A4D:
            raise ValueError("netio.sys does not contain a readable MZ header")

        e_lfanew = cls._u32(layer, base + 0x3C)
        if e_lfanew is None or cls._u32(layer, base + e_lfanew) != 0x4550:
            raise ValueError("netio.sys PE header is unreadable")

        optional = base + e_lfanew + 24
        magic = cls._u16(layer, optional)
        if magic == 0x20B:
            data_directory = optional + 112
        elif magic == 0x10B:
            data_directory = optional + 96
        else:
            raise ValueError("unsupported netio.sys PE optional-header format")

        export_rva = cls._u32(layer, data_directory)
        if not export_rva:
            raise ValueError("netio.sys export directory is unavailable")

        directory = base + export_rva
        function_count = cls._u32(layer, directory + 20) or 0
        name_count = cls._u32(layer, directory + 24) or 0
        function_rva = cls._u32(layer, directory + 28)
        name_rva = cls._u32(layer, directory + 32)
        ordinal_rva = cls._u32(layer, directory + 36)

        if None in (function_rva, name_rva, ordinal_rva):
            raise ValueError("netio.sys export directory fields are unreadable")

        exports = {}
        for index in range(min(int(name_count), 20000)):
            current_name_rva = cls._u32(layer, base + name_rva + index * 4)
            ordinal = cls._u16(layer, base + ordinal_rva + index * 2)
            if (
                current_name_rva is None
                or ordinal is None
                or ordinal >= function_count
            ):
                continue

            name = cls._cstring(layer, base + current_name_rva)
            current_function_rva = cls._u32(
                layer, base + function_rva + ordinal * 4
            )
            if name and current_function_rva is not None:
                exports[name] = base + current_function_rva

        return exports

    @classmethod
    def _follow_thunk(cls, layer, address):
        """Follows common x64 JMP thunks, with a strict four-hop bound."""
        current = cls._norm(layer, address)
        seen = {current}

        for _ in range(4):
            code = cls._read(layer, current, 16)
            if len(code) < 6:
                break

            if code[0] == 0xE9:
                displacement = struct.unpack_from("<i", code, 1)[0]
                target = current + 5 + displacement
            elif code[0] == 0xEB:
                displacement = struct.unpack_from("<b", code, 1)[0]
                target = current + 2 + displacement
            elif code[:2] == b"\xff\x25":
                displacement = struct.unpack_from("<i", code, 2)[0]
                slot = cls._norm(layer, current + 6 + displacement)
                target = cls._u64(layer, slot)
                if not target:
                    break
            else:
                break

            current = cls._norm(layer, target)
            if current in seen:
                break
            seen.add(current)

        return current

    @classmethod
    def _rip_global_candidates(cls, layer, function):
        """Finds MOV/LEA RIP-relative references in FeGetWfpGlobalPtr."""
        code = cls._read(layer, function, 0x80)
        candidates = []

        for index in range(max(0, len(code) - 7)):
            rex = code[index]
            opcode = code[index + 1]
            modrm = code[index + 2]

            if rex not in range(0x48, 0x50):
                continue
            if opcode not in (0x8B, 0x8D):
                continue
            if (modrm & 0xC7) != 0x05:
                continue

            displacement = struct.unpack_from("<i", code, index + 3)[0]
            reference = cls._norm(layer, function + index + 7 + displacement)

            if opcode == 0x8B:
                candidate = cls._u64(layer, reference)
            else:
                candidate = reference

            if candidate:
                candidate = cls._norm(layer, candidate)
                if cls._read(layer, candidate, 0x80):
                    candidates.append(candidate)

        return list(dict.fromkeys(candidates))

    @staticmethod
    def _is_capacity(value):
        return (
            isinstance(value, int)
            and WfpCallouts.MIN_CAPACITY <= value <= WfpCallouts.MAX_CAPACITY
            and (value & (value - 1)) == 0
        )

    @staticmethod
    def _module_for(address, module_ranges):
        for base, end, name in module_ranges:
            if base <= address < end:
                return name, address - base
        return "", 0

    @classmethod
    def _score_table_candidate(
        cls, layer, table, capacity, module_ranges
    ):
        """Scores a possible 0x60 callout table without using any callout IDs."""
        sample_count = min(capacity, 512)
        active_count = 0
        active_with_callback_module = 0
        classify_module_count = 0
        notify_module_count = 0
        active_nonzero_type = 0

        for index in range(sample_count):
            entry = table + index * cls.ENTRY_STRIDE
            raw = cls._read(layer, entry, cls.ENTRY_STRIDE)
            if len(raw) != cls.ENTRY_STRIDE:
                return None

            callout_type = struct.unpack_from("<I", raw, cls.CALLOUT_TYPE_OFFSET)[0]
            enabled = struct.unpack_from("<I", raw, cls.ENABLED_OFFSET)[0]
            classify = struct.unpack_from("<Q", raw, cls.CLASSIFY_OFFSET)[0]
            notify = struct.unpack_from("<Q", raw, cls.NOTIFY_OFFSET)[0]
            flow_delete = struct.unpack_from("<Q", raw, cls.FLOW_DELETE_OFFSET)[0]
            aux = struct.unpack_from("<Q", raw, cls.AUX_CALLBACK_OFFSET)[0]

            callback_modules = 0
            for pointer, label in (
                (classify, "classify"),
                (notify, "notify"),
                (flow_delete, "flow"),
                (aux, "aux"),
            ):
                if not pointer:
                    continue
                module, _ = cls._module_for(cls._norm(layer, pointer), module_ranges)
                if module:
                    callback_modules += 1
                    if label == "classify":
                        classify_module_count += 1
                    elif label == "notify":
                        notify_module_count += 1

            if enabled == 1:
                active_count += 1
                if callout_type:
                    active_nonzero_type += 1
                if callback_modules:
                    active_with_callback_module += 1

        if active_count == 0:
            return None

        callback_coverage = active_with_callback_module / active_count
        type_coverage = active_nonzero_type / active_count

        # Fail closed on tables that do not look like the independently
        # corroborated current Windows callout architecture.
        if callback_coverage < 0.70:
            return None

        score = (
            active_count
            + (active_with_callback_module * 2)
            + classify_module_count
            + notify_module_count
            + int(type_coverage * 20)
        )

        return {
            "active_count": active_count,
            "callback_coverage": callback_coverage,
            "type_coverage": type_coverage,
            "classify_module_count": classify_module_count,
            "notify_module_count": notify_module_count,
            "score": score,
        }

    @classmethod
    def _discover_layout(cls, layer, global_candidates, module_ranges):
        """Discovers capacity/table offsets next to one another in gWfpGlobal."""
        candidates = []

        for global_address in global_candidates:
            data = cls._read(layer, global_address, cls.GLOBAL_SCAN_BYTES)
            if len(data) < 0x100:
                continue

            for offset in range(0, len(data) - 16, 8):
                qword = struct.unpack_from("<Q", data, offset)[0]
                capacity = qword & 0xFFFFFFFF
                high = (qword >> 32) & 0xFFFFFFFF

                if high != 0 or not cls._is_capacity(capacity):
                    continue

                table = struct.unpack_from("<Q", data, offset + 8)[0]
                table = cls._norm(layer, table)
                if not table:
                    continue

                if not cls._read(
                    layer,
                    table,
                    min(capacity, 4) * cls.ENTRY_STRIDE,
                ):
                    continue

                score = cls._score_table_candidate(
                    layer, table, capacity, module_ranges
                )
                if score is None:
                    continue

                candidates.append(
                    {
                        "global": global_address,
                        "capacity_offset": offset,
                        "table_offset": offset + 8,
                        "capacity": capacity,
                        "table": table,
                        **score,
                    }
                )

        if not candidates:
            raise ValueError(
                "No supported WFP callout table layout was discovered. "
                "This plugin fails closed on unvalidated layouts."
            )

        candidates.sort(
            key=lambda item: (
                -item["score"],
                -item["callback_coverage"],
                item["capacity_offset"],
            )
        )

        best = candidates[0]

        # Current production support is deliberately limited to the
        # independently validated 0x60 entry family.
        if best["capacity"] > cls.MAX_ENUM_CAPACITY:
            raise ValueError("WFP callout capacity exceeds safe enumeration bound")

        return best

    @staticmethod
    def _config_list(config, name):
        value = config.get(name, None)
        if value is None:
            return []
        return [item for item in value if item is not None]

    def _row_selected(self, callout_id, modules):
        selected_ids = [
            int(value)
            for value in self._config_list(self.config, "callout-id")
        ]
        if selected_ids and callout_id not in selected_ids:
            return False

        selected_modules = [
            str(value).lower()
            for value in self._config_list(self.config, "module")
        ]
        if selected_modules:
            row_modules = {module.lower() for module in modules if module}
            if not row_modules.intersection(selected_modules):
                return False

        return True

    def _generator(self):
        modules_plugin = self._modules()
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]

        module_ranges = []
        netio_base = None

        for module in modules_plugin.Modules.list_modules(
            self.context, self.config["kernel"]
        ):
            try:
                name = module.BaseDllName.get_string()
                base = self._norm(layer, int(module.DllBase))
                size = int(module.SizeOfImage)
            except Exception:
                continue

            module_ranges.append((base, base + size, name))
            if name.lower() == "netio.sys":
                netio_base = base

        if netio_base is None:
            raise ValueError("netio.sys is not present in the kernel module list")

        exports = self._pe_exports(layer, netio_base)
        export = exports.get("FeGetWfpGlobalPtr")
        if export is None:
            raise ValueError(
                "NETIO!FeGetWfpGlobalPtr is not exported by this image"
            )

        resolved = self._follow_thunk(layer, export)
        global_candidates = self._rip_global_candidates(layer, resolved)
        if not global_candidates:
            raise ValueError(
                "Unable to recover gWfpGlobal from FeGetWfpGlobalPtr"
            )

        layout = self._discover_layout(
            layer, global_candidates, module_ranges
        )

        include_inactive = bool(self.config.get("include-inactive", False))

        for callout_id in range(layout["capacity"]):
            entry = layout["table"] + callout_id * self.ENTRY_STRIDE
            raw = self._read(layer, entry, self.ENTRY_STRIDE)
            if len(raw) != self.ENTRY_STRIDE:
                continue

            callout_type = struct.unpack_from(
                "<I", raw, self.CALLOUT_TYPE_OFFSET
            )[0]
            enabled_raw = struct.unpack_from(
                "<I", raw, self.ENABLED_OFFSET
            )[0]
            kernel_enabled = enabled_raw == 1

            if not kernel_enabled and not include_inactive:
                continue

            classify = self._norm(
                layer,
                struct.unpack_from("<Q", raw, self.CLASSIFY_OFFSET)[0],
            )
            notify = self._norm(
                layer,
                struct.unpack_from("<Q", raw, self.NOTIFY_OFFSET)[0],
            )
            flow_delete = self._norm(
                layer,
                struct.unpack_from("<Q", raw, self.FLOW_DELETE_OFFSET)[0],
            )
            aux = self._norm(
                layer,
                struct.unpack_from("<Q", raw, self.AUX_CALLBACK_OFFSET)[0],
            )

            classify_module, classify_offset = (
                self._module_for(classify, module_ranges) if classify else ("", 0)
            )
            notify_module, notify_offset = (
                self._module_for(notify, module_ranges) if notify else ("", 0)
            )
            flow_module, flow_offset = (
                self._module_for(flow_delete, module_ranges)
                if flow_delete
                else ("", 0)
            )
            aux_module, aux_offset = (
                self._module_for(aux, module_ranges) if aux else ("", 0)
            )

            callback_modules = (
                classify_module,
                notify_module,
                flow_module,
                aux_module,
            )
            if not self._row_selected(callout_id, callback_modules):
                continue

            flags = struct.unpack_from("<I", raw, self.FLAGS_OFFSET)[0]
            device_object = self._norm(
                layer,
                struct.unpack_from("<Q", raw, self.DEVICE_OBJECT_OFFSET)[0],
            )
            layer_info = struct.unpack_from("<H", raw, self.LAYER_INFO_OFFSET)[0]
            tfo_incompat = raw[self.TFO_INCOMPAT_OFFSET]

            yield (
                0,
                (
                    callout_id,
                    bool(kernel_enabled),
                    enabled_raw,
                    callout_type,
                    format_hints.Hex(classify),
                    classify_module,
                    format_hints.Hex(classify_offset),
                    format_hints.Hex(notify),
                    notify_module,
                    format_hints.Hex(notify_offset),
                    format_hints.Hex(flow_delete),
                    flow_module,
                    format_hints.Hex(flow_offset),
                    format_hints.Hex(aux),
                    aux_module,
                    format_hints.Hex(aux_offset),
                    flags,
                    format_hints.Hex(device_object),
                    layer_info,
                    tfo_incompat,
                    format_hints.Hex(entry),
                    layout["capacity"],
                    format_hints.Hex(layout["global"]),
                    layout["capacity_offset"],
                    layout["table_offset"],
                    self.ENTRY_STRIDE,
                    "FeGetWfpGlobalPtr+structural-capacity/table+validated-0x60",
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("CalloutId", int),
                ("KernelEnabled", bool),
                ("EnabledRaw", int),
                ("CalloutType", int),
                ("ClassifyFn", format_hints.Hex),
                ("ClassifyModule", str),
                ("ClassifyModuleOffset", format_hints.Hex),
                ("NotifyFn", format_hints.Hex),
                ("NotifyModule", str),
                ("NotifyModuleOffset", format_hints.Hex),
                ("FlowDeleteFn", format_hints.Hex),
                ("FlowDeleteModule", str),
                ("FlowDeleteModuleOffset", format_hints.Hex),
                ("AuxCallback", format_hints.Hex),
                ("AuxModule", str),
                ("AuxModuleOffset", format_hints.Hex),
                ("Flags", int),
                ("DeviceObject", format_hints.Hex),
                ("LayerInfoRaw", int),
                ("TfoIncompatRaw", int),
                ("Entry", format_hints.Hex),
                ("Capacity", int),
                ("WfpGlobal", format_hints.Hex),
                ("CapacityOffset", int),
                ("TableOffset", int),
                ("EntryStride", int),
                ("Discovery", str),
            ],
            self._generator(),
        )
