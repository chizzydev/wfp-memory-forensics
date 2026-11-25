# Contest entry: motivation and why it should win

This repository is intended to be evaluated as **one integrated entry containing three complementary Volatility 3 plugins**.

## The gap

Windows Filtering Platform sits underneath Windows firewalling, endpoint network controls, IPsec, and third-party filtering products.

During memory triage, investigators can already ask questions such as:

- Which processes existed?
- Which modules were loaded?
- Which network endpoints were present?

But a different question can remain unanswered:

> **What WFP policy was in memory when this connection was blocked?**

WFP Memory Forensics adds that policy-facing view.

## Creativity

The submission reconstructs private WFP filter/policy structures from volatile memory and turns them into a usable forensic workflow rather than treating WFP only through live management APIs.

The suite combines low-level reconstruction, deterministic interpretation, and callout inventory.

## Usefulness

A process can still be alive while its telemetry or outbound connection is being denied.

The canonical demo is intentionally simple: a control endpoint remains available while the adjacent target endpoint is blocked. The suite recovers the WFP filter that matches the denied target and explains its `BLOCK` semantics.

That is an investigator-facing answer to a practical "why did the network path die?" question.

## Effort and research depth

The project went beyond producing plausible parser output:

- private Windows WFP memory structures were investigated;
- pool-record persistence after deletion was explicitly tested;
- misleading "allocation means active" semantics were rejected;
- recovery logic was frozen and tested on a held-out Windows build;
- condition and layer metadata were validated at scale;
- a causal memory sample was built with independent network ground truth;
- latest-stable Volatility compatibility was revalidated end to end.

## Completeness

The entry includes:

- three production plugins;
- installation and usage documentation;
- architecture and provenance documentation;
- a canonical demonstrating memory sample distributed separately;
- curated demo outputs;
- exact source/sample hashes;
- latest-stable compatibility evidence;
- an explicit limitations section.

## Clarity

The suite does not hide forensic uncertainty behind a suspicion score.

Where a claim is directly supported, it is stated directly. Where memory persistence creates ambiguity, the boundary is documented.

## Individual Contributor License Agreement

The Volatility Plugin Contest requires a signed Individual Contributor License Agreement.

The signed ICLA is **not committed to this public repository** because it is a contest/legal submission document and may contain personal information. It should be requested from and returned directly to the Volatility Foundation as part of the contest submission.

## Submission note

The three plugins should be evaluated as **one entry**, not three independent entries.
