# RECON — Rapid Exploit Confirmation & Offensive Recon

> Bug bounty workflow automation: Plan → Execute → Correlate → Report

RECON chains standard recon tooling into one workflow. Give it a target and a set of
vulnerability classes; it builds a tool plan, runs the tools, dedupes and prioritizes
what they find, and writes a submission-ready markdown report.

**Project status: early, work in progress.** The planner and the correlator are
deterministic — every decision comes from rule tables in the source, not from a model.
**There is no LLM integration in this repository yet.** See
[Not implemented yet](#not-implemented-yet).

## What works today

- **Planner** — maps the vulnerability classes you pass to nuclei tags and builds the
  tool plan (`internal/planner`). Pure lookup table, no network calls.
- **Executor** — runs nuclei and httpx sequentially via `os/exec` and parses their JSON
  output (`internal/executor`). ffuf is added automatically when `--depth deep`.
- **Correlator** — dedupes findings by template+host, scores them by severity, and
  attaches impact and remediation text from built-in lookup tables
  (`internal/correlator`). PoC output is currently a placeholder `curl` stub.
- **Reporter** — writes `report.md` in a HackerOne/Bugcrowd-style layout, plus one
  `poc/NNN_*.md` file per finding (`internal/reporter`).

## Not implemented yet

Known gaps, listed so this README matches the code:

- LLM-based planning, payload generation, or correlation — not present
- REST API — `cmd/recon` exposes a single `scan` command, no HTTP server
- `findings.json` — the reporter has a `TODO` where this should be written
- subfinder integration — not called anywhere
- Parallel tool execution — `executor.Execute` runs tools one after another
- Config file — flags only; there is no `configs/default.yaml` and no API key handling

## Quick Start

```bash
# Install external tools
make install-tools

# Build
make build

# Scan a target
./build/recon scan target.com -v xss,sqli,ssrf,idor,auth-bypass -d normal

# Output
output/target.com-<timestamp>/
├── report.md          # HackerOne/Bugcrowd-style report
└── poc/
    ├── 001_xss.md
    └── 002_sqli.md
```

Flags:

| Flag | Default | Notes |
|---|---|---|
| `-v, --vuln` | `xss,sqli,ssrf,idor,auth-bypass` | comma-separated vulnerability classes |
| `-d, --depth` | `normal` | `quick`, `normal`, or `deep` (adds ffuf) |

## Vulnerability Classes

Class to nuclei tag mapping, exactly as implemented in `internal/planner/planner.go`:

| Class | Nuclei Tags |
|---|---|
| `xss` | xss, xss-reflected, xss-stored, xss-dom |
| `sqli` | sqli, sql-injection, sqli-blind, sqli-time-based |
| `ssrf` | ssrf, server-side-request-forgery |
| `idor` | idor, broken-object-authorization |
| `auth-bypass` | auth-bypass, authentication-bypass, jwt, session |
| `rce` | rce, remote-code-execution, command-injection |
| `lfi` | lfi, local-file-inclusion, path-traversal |
| `rfi` | rfi, remote-file-inclusion |
| `xxe` | xxe, xml-external-entity |
| `ssti` | ssti, server-side-template-injection |
| `prototype` | prototype-pollution |
| `deserialize` | deserialization, insecure-deserialization |

## Architecture

```
target + vuln classes
      |
      v
  Planner        deterministic map: class -> nuclei tags -> tool plan
      |
      v
  Executor       os/exec nuclei, httpx ( + ffuf when depth=deep ), sequential
      |
      v
  Correlator     dedupe -> severity score -> impact/remediation lookup tables
      |
      v
  Reporter       report.md + poc/*.md
```

## Requirements

- Go 1.22+
- nuclei, httpx, ffuf — install with `make install-tools`
- No API keys required

## Roadmap

Planned, not built yet:

- LLM-backed planner and correlator (plan generation, finding triage, report drafting)
- REST API for integration
- `findings.json` output
- Parallel tool execution

## License

MIT — see [LICENSE](LICENSE).

Built by [@zxchx_](https://x.com/zxchx_) / Miftahur Rizki