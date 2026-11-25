# Architecture

WFP Memory Forensics is intentionally split into three plugins.

## 1. `wfpfilters`: reconstruction

`wfpfilters` owns the low-level WFP filter recovery path. It scans for the private memory representation used by the validated Windows builds, applies structural checks, decodes the filter record, enriches layer/condition metadata, and emits recovered policy fields.

The investigator-facing selectors are layered on top of the same recovery generator rather than implementing a second scanner.

## 2. `wfpcheck`: interpretation

`wfpcheck` consumes the reconstructed WFP view and converts selected semantics into deterministic findings.

It does not use probabilistic scoring or an LLM. A result such as `DIRECT_FILTER_ACTION -> BLOCK` is based on the decoded filter action itself. Direct-action rows are opt-in through `--include-direct`; default output focuses on callout-backed findings.

This plugin exists because raw kernel structures are useful to researchers but slow investigators down during triage.

## 3. `wfpcallouts`: callout inventory

`wfpcallouts` reconstructs the callout registry/inventory associated with the WFP kernel side.

Together, the three plugins cover:

```text
policy record -> investigator meaning -> callout context
```

## Provenance boundary

The design deliberately separates:

- **record recovery**: a structure is recoverable from memory;
- **decoded semantics**: fields such as layer, action, conditions and ports can be decoded;
- **enforcement/activity claims**: require independent evidence and are not inferred solely from pool allocation state.

This distinction was a design requirement, not a documentation afterthought.
