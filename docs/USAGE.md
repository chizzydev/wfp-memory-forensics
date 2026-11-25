# Usage

## Requirements

- Python 3
- Volatility 3
- a supported Windows memory image
- Windows symbols resolvable by Volatility

The final contest source set was validated on Volatility 3 v2.28.2, stable commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`.

## Installation

Use a clean Volatility 3 checkout and copy the plugins into the Windows plugin directory:

```text
src/windows/wfpfilters.py  -> volatility3/framework/plugins/windows/wfpfilters.py
src/windows/wfpcheck.py    -> volatility3/framework/plugins/windows/wfpcheck.py
src/windows/wfpcallouts.py -> volatility3/framework/plugins/windows/wfpcallouts.py
```

Confirm discovery:

```bash
python vol.py -h
```

The command list should include:

```text
windows.wfpfilters.WfpFilters
windows.wfpcheck.WfpCheck
windows.wfpcallouts.WfpCallouts
```

## `windows.wfpfilters.WfpFilters`

Basic reconstruction:

```bash
python vol.py -f <memory-image> windows.wfpfilters.WfpFilters
```

Useful investigator selectors supported by the final plugin include filter ID, action, layer, port, protocol, freed-only, and unresolved-only filtering.

Example:

```bash
python vol.py -f <memory-image> windows.wfpfilters.WfpFilters --filter-id <filter-id>
```

For machine-readable output:

```bash
python vol.py -q -r json -f <memory-image> windows.wfpfilters.WfpFilters
```

## `windows.wfpcheck.WfpCheck`

Default output focuses on callout-backed filters. Direct PERMIT/BLOCK rows are intentionally opt-in.

Canonical direct-action reproduction using the separately distributed demonstrating sample:

```bash
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpcheck.WfpCheck --include-direct --select-filter-id 67913
```

The canonical controlled sample produces exactly one selected row for filter `67913` with finding `DIRECT_FILTER_ACTION` and effective meaning `BLOCK`.

## `windows.wfpcallouts.WfpCallouts`

Inventory WFP callouts:

```bash
python vol.py -f <memory-image> windows.wfpcallouts.WfpCallouts
```

The canonical sample produces 91 rows.

## First troubleshooting step

Always verify the image itself first:

```bash
python vol.py -f <memory-image> windows.info.Info
```

If Volatility cannot layer/symbolize the image, resolve that before diagnosing these plugins.

## Reproducibility

Use the canonical sample hash in `sample/SHA256SUMS.txt` and compare the semantic expectations in `validation/manifest.json`.
