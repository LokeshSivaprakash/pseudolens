# Sample Corpus

All samples are sourced from public malware repositories (MalwareBazaar).
Files themselves are never committed to this repo (`samples/` is gitignored)
— this file is the chain-of-custody record.

| # | SHA256 | Family | Source | First seen | Rationale |
|---|--------|--------|--------|------------|-----------|
| 1 | `1d5145cd3a353fa36fe6c6583af1846336426a7cb94f5ed08f16ff7b7ebe4cb7` | AgentTesla | MalwareBazaar | 2022-02-15 | Infostealer/keylogger, PE .NET exe, well-documented family, 4+ years of public analysis |
| 2 | `72595c18a683069151fb1efa85766b12ee3519f1f89ddfd2338d19aac368b8c8` | NanoCore | MalwareBazaar | 2021-11-28 | RAT, PE exe, 27/28 AV detection, high-confidence classic RAT for architectural diversity |
| 3 | `3257e394aa928eda420a3c2bc7ff320a3009e69bb9513ba42fd0f68f780adea0` | Emotet (Heodo) | MalwareBazaar | 2022-04-24 | Loader/dropper, PE exe, historically significant family (2021 law enforcement takedown) |

## Selection criteria
- Old (2+ years), well-documented families with existing public analysis to validate findings against.
- Already defanged / widely known — no zero-days, no novel or live threats.
- Diversity of behavior: stealer, RAT, and loader — exercises different parts of the analysis pipeline.
