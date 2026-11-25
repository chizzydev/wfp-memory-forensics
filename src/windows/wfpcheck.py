# This file is Copyright 2026 chizzydev and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
"""Cross-correlates reconstructed WFP filters with kernel callout registrations.

This plugin composes the suite's validated windows.wfpfilters and
windows.wfpcallouts implementations. It performs deterministic correlation only:
no AI scoring, no "suspiciousness" heuristic, and no dependency on live WFP XML.

Default output focuses on filters whose actions invoke WFP callouts. Direct
PERMIT/BLOCK rows and unreferenced kernel callouts are optional.
"""

import json
import logging

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import wfpfilters, wfpcallouts

vollog = logging.getLogger(__name__)


class WfpCheck(interfaces.plugins.PluginInterface):
    """Explains WFP filter policy together with kernel callout registration state."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="wfpfilters",
                component=wfpfilters.WfpFilters,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="wfpcallouts",
                component=wfpcallouts.WfpCallouts,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="include-direct",
                description="Also include direct non-callout filter actions such as PERMIT/BLOCK",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="include-unreferenced-callouts",
                description="Also emit kernel-enabled callouts not referenced by reconstructed non-free filter records",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="only-unregistered",
                description="Show only filters whose callout action has no kernel-enabled callout registration",
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="select-filter-id",
                element_type=int,
                description="Filter ID(s) to include",
                optional=True,
            ),
            requirements.ListRequirement(
                name="select-callout-id",
                element_type=int,
                description="Callout ID(s) to include",
                optional=True,
            ),
            requirements.ListRequirement(
                name="select-layer",
                element_type=str,
                description="Layer name(s) to include; short names such as ALE_AUTH_CONNECT_V4 are accepted",
                optional=True,
            ),
            requirements.ListRequirement(
                name="select-action",
                element_type=str,
                description="Action name(s) to include; short names such as CALLOUT_TERMINATING are accepted",
                optional=True,
            ),
            requirements.ListRequirement(
                name="select-module",
                element_type=str,
                description="Callback owner module(s) to include",
                optional=True,
            ),
        ]

    @staticmethod
    def _config_list(config, name):
        value = config.get(name, None)
        if value is None:
            return []
        return [item for item in value if item is not None]

    @staticmethod
    def _is_callout_action(action):
        return str(action).upper().startswith("FWP_ACTION_CALLOUT_")

    @staticmethod
    def _short_action(action):
        prefix = "FWP_ACTION_"
        action = str(action)
        return action[len(prefix):] if action.startswith(prefix) else action

    @staticmethod
    def _short_layer(layer):
        prefix = "FWPS_LAYER_"
        layer = str(layer)
        return layer[len(prefix):] if layer.startswith(prefix) else layer

    @classmethod
    def _match_name(cls, value, selector, prefix):
        value = str(value).upper()
        selector = str(selector).strip().upper()
        if not selector:
            return True
        if not selector.startswith(prefix):
            selector = prefix + selector
        return value == selector

    @classmethod
    def _callout_record(cls, raw):
        return {
            "callout_id": int(raw[0]),
            "kernel_enabled": bool(raw[1]),
            "enabled_raw": int(raw[2]),
            "callout_type": int(raw[3]),
            "classify_fn": int(raw[4]),
            "classify_module": str(raw[5]),
            "classify_module_offset": int(raw[6]),
            "notify_fn": int(raw[7]),
            "notify_module": str(raw[8]),
            "notify_module_offset": int(raw[9]),
            "flow_delete_fn": int(raw[10]),
            "flow_delete_module": str(raw[11]),
            "flow_delete_module_offset": int(raw[12]),
            "aux_fn": int(raw[13]),
            "aux_module": str(raw[14]),
            "aux_module_offset": int(raw[15]),
            "flags": int(raw[16]),
            "device_object": int(raw[17]),
            "entry": int(raw[20]),
        }

    @classmethod
    def _filter_record(cls, filter_plugin, raw):
        try:
            conditions = json.loads(raw[19])
        except (TypeError, ValueError, json.JSONDecodeError):
            conditions = []

        projection = filter_plugin._condition_projection(conditions)
        return {
            "filter_id": int(raw[5]),
            "layer_id": int(raw[6]),
            "layer_name": str(raw[7]),
            "action": str(raw[8]),
            "action_type": int(raw[9]),
            "weight": str(raw[10]),
            "filter_flags": int(raw[14]),
            "conditions_count": int(raw[15]),
            "conditions_readable": bool(raw[17]),
            "conditions": str(raw[18]),
            "callout_id": int(raw[20]),
            "recovery": filter_plugin._recovery_label(str(raw[1])),
            "pool_state": str(raw[1]),
            "protocol": str(projection["protocol"]),
            "local_address": str(projection["local_address"]),
            "local_port": (
                int(projection["local_port"])
                if projection["local_port"] is not None
                else 0
            ),
            "remote_address": str(projection["remote_address"]),
            "remote_port": (
                int(projection["remote_port"])
                if projection["remote_port"] is not None
                else 0
            ),
            "app_id": str(projection["app_id"]),
            "user_id": str(projection["user_id"]),
            "package_id": str(projection["package_id"]),
            "direction": str(projection["direction"]),
            "condition_resolution": (
                f"{projection['resolved_count']}/{projection['total_count']}"
            ),
        }

    def _selected(self, filter_record, callout_record):
        filter_ids = [
            int(item)
            for item in self._config_list(self.config, "select-filter-id")
        ]
        if filter_ids and filter_record["filter_id"] not in filter_ids:
            return False

        callout_ids = [
            int(item)
            for item in self._config_list(self.config, "select-callout-id")
        ]
        if callout_ids and filter_record["callout_id"] not in callout_ids:
            return False

        layers = self._config_list(self.config, "select-layer")
        if layers and not any(
            self._match_name(filter_record["layer_name"], item, "FWPS_LAYER_")
            for item in layers
        ):
            return False

        actions = self._config_list(self.config, "select-action")
        if actions and not any(
            self._match_name(filter_record["action"], item, "FWP_ACTION_")
            for item in actions
        ):
            return False

        modules = [
            str(item).lower()
            for item in self._config_list(self.config, "select-module")
        ]
        if modules:
            if callout_record is None:
                return False
            row_modules = {
                callout_record["classify_module"].lower(),
                callout_record["notify_module"].lower(),
                callout_record["flow_delete_module"].lower(),
                callout_record["aux_module"].lower(),
            }
            if not row_modules.intersection(modules):
                return False

        return True

    @staticmethod
    def _explanation(record, callout):
        filter_id = record["filter_id"]
        action = record["action"]
        layer = record["layer_name"]
        conditions = record["conditions"] or "(no decoded conditions)"
        provenance = "Pool record recovered; active policy membership is unproven"

        if not WfpCheck._is_callout_action(action):
            return (
                f"WfpF record {filter_id} describes {action} at {layer}; "
                f"{provenance}; conditions: {conditions}"
            )

        callout_id = record["callout_id"]
        if callout is None:
            return (
                f"WfpF record {filter_id} references callout ID {callout_id} at {layer}; "
                f"no kernel-enabled registration reconstructed; {provenance}; "
                f"conditions: {conditions}"
            )

        owners = []
        for role, module in (
            ("classify", callout["classify_module"]),
            ("notify", callout["notify_module"]),
            ("flow-delete", callout["flow_delete_module"]),
            ("aux", callout["aux_module"]),
        ):
            if module:
                owners.append(f"{role}={module}")
        owner_text = ", ".join(owners) if owners else "callback owner unresolved"
        return (
            f"WfpF record {filter_id} references kernel-enabled callout ID {callout_id} "
            f"at {layer}; {owner_text}; {provenance}; conditions: {conditions}"
        )

    def _generator(self):
        # Both suite components receive this plugin's config path. Their
        # optional selectors use different names and therefore remain at
        # defaults, so correlation starts from the full default non-free datasets.
        filter_plugin = wfpfilters.WfpFilters(
            self.context, self.config_path, self._progress_callback
        )
        callout_plugin = wfpcallouts.WfpCallouts(
            self.context, self.config_path, self._progress_callback
        )

        callouts = {}
        for _depth, raw in callout_plugin._generator():
            record = self._callout_record(raw)
            if record["kernel_enabled"]:
                callouts[record["callout_id"]] = record

        filters = []
        referenced_callouts = set()
        for _depth, raw in filter_plugin._generator():
            record = self._filter_record(filter_plugin, raw)
            filters.append(record)
            if self._is_callout_action(record["action"]) and record["callout_id"] > 0:
                referenced_callouts.add(record["callout_id"])

        include_direct = bool(self.config.get("include-direct", False))
        only_unregistered = bool(self.config.get("only-unregistered", False))

        for record in filters:
            is_callout = self._is_callout_action(record["action"])
            callout = (
                callouts.get(record["callout_id"])
                if is_callout and record["callout_id"] > 0
                else None
            )

            if not is_callout and not include_direct:
                continue
            if only_unregistered and (not is_callout or callout is not None):
                continue
            if not self._selected(record, callout):
                continue

            if not is_callout:
                finding = "DIRECT_FILTER_ACTION"
                kernel_state = "NOT_APPLICABLE"
                effective = self._short_action(record["action"])
            elif callout is None:
                finding = "CALLOUT_FILTER_NOT_KERNEL_REGISTERED"
                kernel_state = "NOT_KERNEL_REGISTERED"
                effective = "BLOCK_IF_UNREGISTERED"
            else:
                finding = "CALLOUT_FILTER_KERNEL_REGISTERED"
                kernel_state = "KERNEL_ENABLED"
                effective = "CALLOUT_DISPATCH"

            yield (
                0,
                (
                    finding,
                    record["filter_id"],
                    self._short_action(record["action"]),
                    self._short_layer(record["layer_name"]),
                    record["protocol"],
                    record["local_address"],
                    record["local_port"],
                    record["remote_address"],
                    record["remote_port"],
                    record["app_id"],
                    record["user_id"],
                    record["package_id"],
                    record["direction"],
                    record["callout_id"],
                    kernel_state,
                    (
                        callout["callout_type"]
                        if callout is not None
                        else 0
                    ),
                    (
                        format_hints.Hex(callout["classify_fn"])
                        if callout is not None
                        else format_hints.Hex(0)
                    ),
                    callout["classify_module"] if callout is not None else "",
                    (
                        format_hints.Hex(callout["notify_fn"])
                        if callout is not None
                        else format_hints.Hex(0)
                    ),
                    callout["notify_module"] if callout is not None else "",
                    (
                        format_hints.Hex(callout["flow_delete_fn"])
                        if callout is not None
                        else format_hints.Hex(0)
                    ),
                    callout["flow_delete_module"] if callout is not None else "",
                    callout["flags"] if callout is not None else 0,
                    effective,
                    record["condition_resolution"],
                    record["conditions"],
                    record["weight"],
                    record["filter_flags"],
                    record["recovery"],
                    self._explanation(record, callout),
                ),
            )

        if bool(self.config.get("include-unreferenced-callouts", False)):
            filter_ids = self._config_list(self.config, "select-filter-id")
            layers = self._config_list(self.config, "select-layer")
            actions = self._config_list(self.config, "select-action")
            # A callout-only row has no filter dimension, so filter/layer/action
            # selectors intentionally suppress it.
            if not filter_ids and not layers and not actions and not only_unregistered:
                selected_callouts = [
                    int(item)
                    for item in self._config_list(
                        self.config, "select-callout-id"
                    )
                ]
                selected_modules = {
                    str(item).lower()
                    for item in self._config_list(
                        self.config, "select-module"
                    )
                }

                for callout_id in sorted(set(callouts) - referenced_callouts):
                    callout = callouts[callout_id]

                    if selected_callouts and callout_id not in selected_callouts:
                        continue

                    row_modules = {
                        callout["classify_module"].lower(),
                        callout["notify_module"].lower(),
                        callout["flow_delete_module"].lower(),
                        callout["aux_module"].lower(),
                    }
                    if selected_modules and not row_modules.intersection(
                        selected_modules
                    ):
                        continue

                    owners = [
                        value
                        for value in (
                            callout["classify_module"],
                            callout["notify_module"],
                            callout["flow_delete_module"],
                            callout["aux_module"],
                        )
                        if value
                    ]
                    owner_text = ", ".join(sorted(set(owners))) or "unresolved"

                    yield (
                        0,
                        (
                            "KERNEL_CALLOUT_UNREFERENCED_BY_RECOVERED_WFPF",
                            0,
                            "",
                            "",
                            "",
                            "",
                            0,
                            "",
                            0,
                            "",
                            "",
                            "",
                            "",
                            callout_id,
                            "KERNEL_ENABLED",
                            callout["callout_type"],
                            format_hints.Hex(callout["classify_fn"]),
                            callout["classify_module"],
                            format_hints.Hex(callout["notify_fn"]),
                            callout["notify_module"],
                            format_hints.Hex(callout["flow_delete_fn"]),
                            callout["flow_delete_module"],
                            callout["flags"],
                            "KERNEL_REGISTRATION_ONLY",
                            "0/0",
                            "",
                            "",
                            0,
                            "N/A",
                            (
                                f"Kernel-enabled callout ID {callout_id} has no "
                                f"reference among the reconstructed WfpF pool "
                                f"records; callback owners: {owner_text}"
                            ),
                        ),
                    )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Finding", str),
                ("FilterId", int),
                ("Action", str),
                ("Layer", str),
                ("Protocol", str),
                ("LocalAddress", str),
                ("LocalPort", int),
                ("RemoteAddress", str),
                ("RemotePort", int),
                ("AppId", str),
                ("UserId", str),
                ("PackageId", str),
                ("Direction", str),
                ("CalloutId", int),
                ("KernelCalloutState", str),
                ("CalloutType", int),
                ("ClassifyFn", format_hints.Hex),
                ("ClassifyModule", str),
                ("NotifyFn", format_hints.Hex),
                ("NotifyModule", str),
                ("FlowDeleteFn", format_hints.Hex),
                ("FlowDeleteModule", str),
                ("CalloutFlags", int),
                ("EffectiveMeaning", str),
                ("ConditionResolution", str),
                ("Conditions", str),
                ("Weight", str),
                ("FilterFlags", int),
                ("Recovery", str),
                ("Explanation", str),
            ],
            self._generator(),
        )
