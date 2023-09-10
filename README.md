# Zircolite-Rules

This repository uses Github Actions to generate periodically updated Sigma rulesets in Zircolite format.

## Default rulesets

With the exceptions of the last two, these rulesets have been generated with `sigmac` wich is available in the [official sigma repository](https://github.com/SigmaHQ/legacy-sigmatools).
The rulesets with "pysigma" in their names have been generated with the news [SQLite backend](https://github.com/wagga40/pySigma-backend-sqlite) for [pySigma](https://github.com/SigmaHQ/pySigma).

:warning: **These rulesets are given "as is" to help new analysts to discover SIGMA and Zircolite. They are not filtered for slow rules, rules with a lot of false positives etc. If you know what you do, you SHOULD generate your own rulesets.**

- `rules_windows_generic_full.json` : Full SIGMA ruleset from the "**Windows**", "rules-emerging-threats" and "rules-threat-hunting" directories of the official repository (no SYSMON rewriting)
- `rules_windows_generic_high.json` : Only level high and above SIGMA rules from the "**Windows**", "rules-emerging-threats" and "rules-threat-hunting" directories of the official repository (no SYSMON rewriting)
- `rules_windows_generic_medium.json` : Only level medium and above SIGMA rules from the "**Windows**", "rules-emerging-threats" and "rules-threat-hunting" directories of the official repository (no SYSMON rewriting)
- `rules_windows_generic.json` : Same file as `rules_windows_generic_high.json`
- `rules_windows_sysmon_full.json` : Full SIGMA ruleset from the "**Windows**", "rules-emerging-threats" and "rules-threat-hunting" directories of the official repository  (SYSMON)
- `rules_windows_sysmon_high.json` : Only level high and above SIGMA rules from the "**Windows**", "rules-emerging-threats" and "rules-threat-hunting" directories of the official repository (SYSMON)
- `rules_windows_sysmon_medium.json` : Only level medium and above SIGMA rules from the "**Windows**", "rules-emerging-threats" and "rules-threat-hunting" directories of the official repository (SYSMON)
- `rules_windows_sysmon.json` : Same file as `rules_windows_sysmon_high.json`
- `rules_windows_sysmon_pysigma.json` : Same file as `rules_windows_sysmon_full.json` but **generated with pySigma**
- `rules_windows_generic_pysigma` : Same file as `rules_windows_generic_full.json` but **generated with pySigma**
- `rules_linux.json` : Linux rules converted "as is"