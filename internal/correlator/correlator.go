package correlator

import (
	"fmt"
	"strings"

	"github.com/mift-enterprise/recon/internal/executor"
)

type CorrelatedFinding struct {
	executor.Finding
	Confidence   float64 `json:"confidence"`
	Priority     int     `json:"priority"` // 1=critical, 5=info
	PoC          string  `json:"poc"`
	Impact       string  `json:"impact"`
	Remediation  string  `json:"remediation"`
}

func Correlate(findings []executor.Finding) []CorrelatedFinding {
	// 1. Dedupe by template + host
	deduped := dedupe(findings)

	// 2. Score & prioritize
	scored := score(deduped)

	// 3. Generate PoC (placeholder - LLM will enhance)
	for i := range scored {
		scored[i].PoC = generatePoC(&scored[i])
		scored[i].Impact = generateImpact(&scored[i])
		scored[i].Remediation = generateRemediation(&scored[i])
	}

	return scored
}

func dedupe(findings []executor.Finding) []executor.Finding {
	seen := make(map[string]bool)
	var result []executor.Finding

	for _, f := range findings {
		key := f.Template + "|" + f.Host
		if f.Template == "" {
			key = f.Type + "|" + f.Host
		}
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

func score(findings []executor.Finding) []CorrelatedFinding {
	severityWeight := map[string]float64{
		"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0,
	}

	var result []CorrelatedFinding
	for _, f := range findings {
		weight := severityWeight[strings.ToLower(f.Severity)]
		if weight == 0 {
			weight = 1.0
		}

		conf := weight / 10.0
		priority := 5
		if weight >= 7.5 {
			priority = 1
		} else if weight >= 5.0 {
			priority = 2
		} else if weight >= 2.5 {
			priority = 3
		} else {
			priority = 4
		}

		result = append(result, CorrelatedFinding{
			Finding:    f,
			Confidence: conf,
			Priority:   priority,
		})
	}
	return result
}

func generatePoC(f *CorrelatedFinding) string {
	return fmt.Sprintf("# PoC for %s\n\n```bash\ncurl -X GET \"%s\"\n```\n", f.Template, f.MatchedAt)
}

func generateImpact(f *CorrelatedFinding) string {
	impacts := map[string]string{
		"xss":           "Steal session cookies, perform actions as victim, deface pages",
		"sqli":          "Extract database, bypass auth, RCE via SQL functions",
		"ssrf":          "Access internal services, cloud metadata, bypass firewalls",
		"idor":          "Access other users' data, horizontal/vertical privilege escalation",
		"auth-bypass":   "Full account takeover, admin panel access, session hijacking",
		"rce":           "Full server compromise, lateral movement, persistence",
		"lfi":           "Read sensitive files, source code disclosure, RCE via log poisoning",
		"rfi":           "Remote code execution via malicious file inclusion",
		"xxe":           "File read, SSRF, DoS, RCE via deserialization",
		"ssti":          "Remote code execution via template engine",
		"prototype":     "RCE, DoS, logic bypass via prototype pollution",
		"deserialize":   "RCE via gadget chains, DoS",
	}

	for k, v := range impacts {
		if strings.Contains(strings.ToLower(f.Template), k) {
			return v
		}
	}
	return "Impact varies based on context and exploitation chain"
}

func generateRemediation(f *CorrelatedFinding) string {
	remediation := map[string]string{
		"xss":           "Implement CSP, sanitize input, encode output, use HTTPOnly cookies",
		"sqli":          "Use parameterized queries, prepared statements, ORM, least privilege DB user",
		"ssrf":          "Allowlist destinations, block internal IPs, disable redirects, use egress proxy",
		"idor":          "Implement object-level authorization checks, use indirect references",
		"auth-bypass":   "Enforce MFA, secure session management, validate JWT signatures, rate limit auth",
		"rce":           "Disable dangerous functions, sandbox execution, input validation, WAF",
		"lfi":           "Validate file paths, use allowlist, disable include/require user input",
		"rfi":           "Disable allow_url_include, validate input, use local files only",
		"xxe":           "Disable external entities, use safe XML parsers, update libraries",
		"ssti":          "Sandbox template engine, disable dangerous filters, use logic-less templates",
		"prototype":     "Freeze Object.prototype, use Map/Object.create(null), validate input",
		"deserialize":   "Avoid deserialization of untrusted data, use safe libraries, integrity checks",
	}

	for k, v := range remediation {
		if strings.Contains(strings.ToLower(f.Template), k) {
			return v
		}
	}
	return "Apply defense in depth: input validation, output encoding, least privilege, monitoring"
}