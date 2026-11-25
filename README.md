# WFP Memory Forensics for Volatility 3

**Reconstruct Windows Filtering Platform policy from memory, turn recovered filter semantics into investigator-facing findings, and inventory WFP callouts.**

This repository contains three complementary Volatility 3 plugins that are intended to be evaluated and used as **one integrated forensic suite**:

| Plugin | Purpose |
| --- | --- |
| `windows.wfpfilters.WfpFilters` | Reconstructs memory-resident WFP filter/policy records and decodes layers, actions, conditions, identities, protocols, addresses, and ports. |
| `windows.wfpcheck.WfpCheck` | Correlates reconstructed filter/callout state and, with `--include-direct`, emits deterministic direct actions such as `BLOCK`. |
| `windows.wfpcallouts.WfpCallouts` | Reconstructs the WFP kernel callout inventory from memory. |

## The forensic question

Process and socket views can tell an investigator **what existed**. They do not necessarily explain **which packet-filtering policy was present when a connection was denied**.

WFP Memory Forensics adds that missing policy layer.

In the canonical controlled demonstration, one client kept a control connection available on port `8781` while repeated attempts to the adjacent target service on `8782` were denied. A dynamic WFP filter was then recovered from RAM as:

- Filter ID `67913`
- action `BLOCK`
- layer `ALE_AUTH_CONNECT_V4`
- protocol `TCP/6`
- remote port `8782`
- two decoded conditions

`wfpcheck`, with direct actions explicitly enabled, surfaced the same object as `DIRECT_FILTER_ACTION` with effective meaning `BLOCK`. After the memory evidence was sealed, termination of the filter owner removed the dynamic policy and the target service became reachable again.

That gives the workflow a causal ground truth rather than a parser-only demonstration.

## Why three plugins?

The suite deliberately separates three jobs:

1. **Reconstruction** — recover and decode WFP policy records.
2. **Interpretation** — present deterministic findings without inventing "AI suspiciousness".
3. **Callout inventory** — expose the kernel callout side of WFP.

The low-level recovery path and the investigator-facing presentation path are kept separate so presentation features do not silently redefine forensic provenance.

## Quick start

Validated against **Volatility 3 v2.28.2**, whose `stable` branch resolved to commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75` during final compatibility testing.

Copy the three files from `src/windows/` into:

```text
volatility3/framework/plugins/windows/
```

Then run:

```bash
python vol.py -f <memory-image> windows.wfpfilters.WfpFilters
python vol.py -f <memory-image> windows.wfpcheck.WfpCheck --include-direct
python vol.py -f <memory-image> windows.wfpcallouts.WfpCallouts
```

JSON output is useful for automation and reproduction:

```bash
python vol.py -q -r json -f <memory-image> windows.wfpfilters.WfpFilters
```

See [docs/USAGE.md](docs/USAGE.md) for detailed installation and filters. Exact canonical-sample reproduction commands are in [sample/README.md](sample/README.md).

## Validation at a glance

The final source set passed syntax, discovery, help, execution, and semantic validation on the canonical Windows memory image using the current stable Volatility 3 framework at the time of validation.

The held-out cross-build validation recovered **580/580 non-boot live filters**, resolved **580/580 layer names**, resolved **2233/2233 condition fields**, and recovered **4/4 held-out filters with matching semantics**.

The canonical demo reproduced:

- filter `67913`
- `BLOCK`
- `ALE_AUTH_CONNECT_V4`
- `TCP/6`
- remote port `8782`
- `2/2` conditions
- `DIRECT_FILTER_ACTION -> BLOCK`
- `91` WFP callout rows

See [docs/VALIDATION.md](docs/VALIDATION.md) and [validation/manifest.json](validation/manifest.json).

## Important claim boundary

A recoverable WFP allocation in memory is **not automatically evidence that the policy is currently active or enforced**. Freed or stale memory can survive.

This suite reports what can be justified from the recovered structure and its decoded semantics. The canonical demo's enforcement claim comes from an independently controlled before/after experiment, not from allocation state alone.

Known boundary: boot-time filters are outside the current runtime recovery path. In held-out validation, the only missing live IDs were the boot-time filters.

## Canonical sample

The demonstrating memory image is intentionally **not committed to Git**.

- file: `wfp-memory-forensics-canonical-win11-26300.9974.elf`
- size: `4438826344` bytes (4.134 GiB)
- SHA-256: `2BD6C3ABE1AA694F80C7AA2E8D31285F174593649CA61D223BE29D7492BA9187`

The sample is distributed separately to contest reviewers. See [sample/README.md](sample/README.md).

## 2026 Volatility Plugin Contest

This repository is prepared as **one integrated entry** containing three complementary plugins.

The contest write-up is in [docs/CONTEST.md](docs/CONTEST.md). The contest-required signed Individual Contributor License Agreement is handled directly with the Volatility Foundation and is intentionally not stored in this public repository.

## Source integrity

Final source hashes:

```text
BD5703A884D55F652328F3326DDDD30F59AD1D6038D03DDAA88E401C74128B7C  src/windows/wfpfilters.py
7E1683A9A5F02DAD8C63034018F18850A39F7A6A458E95648BACA61AE875CF30  src/windows/wfpcheck.py
F71FC85972D0849A849080818504A7C171CA12351500EB0E16D7EC16D8BAA691  src/windows/wfpcallouts.py
```

Run:

```bash
python scripts/verify_source_hashes.py
```

to verify the three plugin files.

## Documentation

- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Validation and claim boundaries](docs/VALIDATION.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Contest motivation / why it should win](docs/CONTEST.md)
- [Memory sample](sample/README.md)
- [Canonical demo outputs](examples/canonical-demo/README.md)

## License

This project is licensed under the **Volatility Software License 1.0**. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).

Volatility 3 itself is a separate project of the Volatility Foundation.
