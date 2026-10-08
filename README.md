# RECON — Rapid Exploit Confirmation & Offensive Recon

> Agentic bug bounty assistant: **Plan → Execute → Correlate → Report**

RECON automates the bug bounty workflow from reconnaissance to report generation, using LLM reasoning for workflow planning, payload generation, and finding correlation.

## Features

- **Planner**: LLM-generated execution plans for target vulnerability classes
- **Executor**: Parallel tool execution (nuclei, httpx, ffuf, subfinder)
- **Correlator**: Deduplication, prioritization, PoC generation, impact assessment
- **Reporter**: H1/Bugcrowd/Intigriti-ready reports (Markdown, JSON, HTML)
- **CLI & API**: Terminal-first, with REST API for integration

## Quick Start

```bash
# Install tools
make install-tools

# Build
make build

# Scan target
./build/recon scan target.com -v xss,sqli,ssrf,idor,auth-bypass -d normal

# Output
./output/target.com-20240115-143000/
├── findings.json
├── report.md          # H1/Bugcrowd format
├── poc/
│   ├── 001_xss.md
│   └── 002_sqli.md
└── summary.txt
```

## Vulnerability Classes Supported

| Class | Nuclei Tags | Description |
|-------|-------------|-------------|
| `xss` | xss, xss-reflected, xss-stored, xss-dom | Cross-site scripting |
| `sqli` | sqli, sql-injection, sqli-blind | SQL injection |
| `ssrf` | ssrf | Server-side request forgery |
| `idor` | idor, broken-object-authorization | Insecure direct object reference |
| `auth-bypass` | auth-bypass, jwt, session | Authentication bypass |
| `rce` | rce, command-injection | Remote code execution |
| `lfi` | lfi, path-traversal | Local file inclusion |
| `rfi` | rfi | Remote file inclusion |
| `xxe` | xxe | XML external entity |
| `ssti` | ssti | Server-side template injection |
| `prototype` | prototype-pollution | Prototype pollution |
| `deserialize` | deserialization | Insecure deserialization |

## Architecture

```
User Input → Planner (LLM) → Executor (Tools) → Correlator (LLM) → Reporter
```

## Configuration

`configs/default.yaml`:
```yaml
claude:
  model: "claude-3-5-sonnet-20241022"
  max_tokens: 8192
tools:
  nuclei:
    rate_limit: 150
    severity: ["critical", "high", "medium"]
  httpx:
    rate_limit: 200
  ffuf:
    rate_limit: 100
```

## Requirements

- Go 1.22+
- nuclei, httpx, ffuf, subfinder (via `make install-tools`)
- Claude API key (for planner/correlator)

## License

MIT — Built by [@zxchx_](https://x.com/zxchx_) / Miftahur Rizki