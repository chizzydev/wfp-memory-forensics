# Validation

The project was validated as a forensic capability rather than as a plugin that merely prints plausible rows.

## Canonical causal demonstration

A controlled Windows 11 test created two adjacent host services:

- control: `10.0.2.2:8781`
- target: `10.0.2.2:8782`

The same client kept the control path available while repeated target connections were denied.

A dynamic WFP `BLOCK` filter was installed at `ALE_AUTH_CONNECT_V4` for TCP remote port `8782`.

The memory image was acquired while the condition was present.

The final suite recovered:

| Assertion | Result |
| --- | --- |
| Filter ID | `67913` |
| Action | `BLOCK` |
| Layer | `ALE_AUTH_CONNECT_V4` |
| Protocol | `TCP/6` |
| Remote port | `8782` |
| Decoded conditions | `2/2` |
| `wfpcheck` finding | `DIRECT_FILTER_ACTION` |
| Effective meaning | `BLOCK` |
| Callout inventory | `91` rows |

After outputs were sealed, the filter owner exited and the target service became reachable again.

The enforcement conclusion therefore comes from independent behavior + lifecycle control + memory reconstruction, not from a pool-allocation heuristic.

Exact final reproduction commands:

```bash
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpfilters.WfpFilters --filter-id 67913
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpcheck.WfpCheck --include-direct --select-filter-id 67913
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpcallouts.WfpCallouts
```

The final public-release gate requires exactly one selected `wfpfilters` row, exactly one selected direct-action `wfpcheck` row, and exactly 91 `wfpcallouts` rows.

## Held-out cross-build validation

A separately held-out Windows 11 26H2 build `26300.9457` was used to test the frozen recovery logic without tuning to the held-out specimen.

Results:

- held-out filters recovered: `4/4`
- held-out semantics matched: `4/4`
- non-boot live filters recovered: `580/580`
- non-boot coverage: `1.0`
- layer names resolved: `580/580`
- condition fields resolved: `2233/2233`
- extra runtime IDs: `0`
- missing IDs matched the boot-time filter set exactly

## Latest-stable compatibility

The final source set was validated against Volatility 3 v2.28.2 / stable commit:

```text
881e970121c16f0932fb9d16fbd5fb258cbcbf75
```

All three plugins:

- compiled successfully;
- were discovered by Volatility;
- exposed working help;
- executed against the canonical memory image;
- reproduced the canonical semantic assertions.

## What the suite does not claim

### Recoverable is not the same as active

A WFP pool record can remain recoverable after policy deletion. The suite therefore does **not** infer "currently active" solely because an allocation is readable.

### Boot-time filter boundary

The validated runtime recovery path does not currently cover boot-time filters. Held-out validation made that boundary explicit instead of hiding missing rows.

### No blind orphan-runtime claim

A separate blind investigation of runtime-only/orphan recovery produced a high-noise candidate space and did not establish a reliable deleted-runtime recovery method. That unproven capability is not advertised here.

## Integrity

Canonical memory SHA-256:

```text
2BD6C3ABE1AA694F80C7AA2E8D31285F174593649CA61D223BE29D7492BA9187
```

Final plugin SHA-256 values are recorded in `validation/source-hashes.sha256`.
