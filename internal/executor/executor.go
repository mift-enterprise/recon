package executor

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mift-enterprise/recon/internal/planner"
)

type Finding struct {
	Tool       string                 `json:"tool"`
	Template   string                 `json:"template,omitempty"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	Host       string                 `json:"host"`
	MatchedAt  string                 `json:"matched_at"`
	Extractor  string                 `json:"extractor,omitempty"`
	Curl       string                 `json:"curl,omitempty"`
	Raw        map[string]interface{} `json:"raw"`
}

func Execute(plan *planner.Plan) []Finding {
	var allFindings []Finding

	for _, tool := range plan.Tools {
		findings := runTool(tool, plan.Target)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

func runTool(tool planner.Tool, target string) []Finding {
	var findings []Finding

	args := make([]string, len(tool.Args))
	copy(args, tool.Args)
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "TARGET", target)
	}

	cmd := exec.Command(tool.Name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[EXEC] %s error: %v\n", tool.Name, err)
	}

	switch tool.Name {
	case "nuclei":
		findings = parseNuclei(out)
	case "httpx":
		findings = parseHttpx(out)
	case "ffuf":
		findings = parseFfuf(out)
	}

	return findings
}

func parseNuclei(out []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			f.Tool = "nuclei"
			findings = append(findings, f)
		}
	}
	return findings
}

func parseHttpx(out []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			f := Finding{
				Tool:  "httpx",
				Type:  "tech-detect",
				Host:  fmt.Sprintf("%v", raw["url"]),
				Raw:   raw,
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func parseFfuf(out []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			f := Finding{
				Tool:  "ffuf",
				Type:  "endpoint",
				Host:  fmt.Sprintf("%v", raw["url"]),
				Raw:   raw,
			}
			findings = append(findings, f)
		}
	}
	return findings
}