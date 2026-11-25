# Compatibility

## Validated framework target

Final compatibility validation used:

- Volatility 3 version: `2.28.2`
- official repository: `https://github.com/volatilityfoundation/volatility3`
- stable commit: `881e970121c16f0932fb9d16fbd5fb258cbcbf75`
- Python: `3.12.10`

At validation time, the official `stable` branch and the latest release tag resolved to the same commit.

## Windows target evidence

The canonical causal sample was captured from Windows 11 Enterprise Evaluation 26H2, build `26300.9974`.

The recovery logic was also exercised against a held-out Windows build `26300.9457`.

## Final import compatibility

The final `wfpcheck.py` imports its sibling plugins from:

```python
from volatility3.plugins.windows import wfpfilters, wfpcallouts
```

This matches the current Volatility 3 Windows-plugin namespace.

## Build sensitivity

The low-level WFP structures used here are private implementation details, not a stable public forensic ABI. Future Windows builds can change those relationships.

That is why the repository publishes the exact validated framework/build context and does not present cross-version compatibility as guaranteed.
