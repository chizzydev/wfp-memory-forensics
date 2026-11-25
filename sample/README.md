# Canonical demonstrating memory sample

The memory image used for the final causal demonstration is not stored in Git because of its size.

## Identity

- file: `wfp-memory-forensics-canonical-win11-26300.9974.elf`
- size: `4438826344` bytes
- size (GiB): `4.134`
- SHA-256: `2BD6C3ABE1AA694F80C7AA2E8D31285F174593649CA61D223BE29D7492BA9187`

## Target

- Windows 11 Enterprise Evaluation 26H2
- build `26300.9974`

## Demonstrated condition

The controlled sample contains the WFP policy used in the canonical demo:

- Filter ID `67913`
- `BLOCK`
- `ALE_AUTH_CONNECT_V4`
- TCP (`6`)
- remote port `8782`
- two decoded conditions

The same capture also yields a 91-row WFP callout inventory.

## Distribution

The sample is delivered separately to contest reviewers.

Anyone receiving the sample should verify the SHA-256 before analysis.

## Expected commands

```bash
python vol.py -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.info.Info
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpfilters.WfpFilters --filter-id 67913
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpcheck.WfpCheck --include-direct --select-filter-id 67913
python vol.py -q -r json -f wfp-memory-forensics-canonical-win11-26300.9974.elf windows.wfpcallouts.WfpCallouts
```
