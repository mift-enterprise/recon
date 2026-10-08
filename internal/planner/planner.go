package planner

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Plan struct {
	Target      string   `json:"target"`
	VulnClasses []string `json:"vuln_classes"`
	Depth       string   `json:"depth"`
	Tools       []Tool   `json:"tools"`
	NucleiTags  []string `json:"nuclei_tags"`
}

type Tool struct {
	Name    string   `json:"name"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
}

var vulnToNucleiTags = map[string][]string{
	"xss":           {"xss", "xss-reflected", "xss-stored", "xss-dom"},
	"sqli":          {"sqli", "sql-injection", "sqli-blind", "sqli-time-based"},
	"ssrf":          {"ssrf", "server-side-request-forgery"},
	"idor":          {"idor", "broken-object-authorization"},
	"auth-bypass":   {"auth-bypass", "authentication-bypass", "jwt", "session"},
	"rce":           {"rce", "remote-code-execution", "command-injection"},
	"lfi":           {"lfi", "local-file-inclusion", "path-traversal"},
	"rfi":           {"rfi", "remote-file-inclusion"},
	"xxe":           {"xxe", "xml-external-entity"},
	"ssti":          {"ssti", "server-side-template-injection"},
	"prototype":     {"prototype-pollution"},
	"deserialize":   {"deserialization", "insecure-deserialization"},
}

func GeneratePlan(target string, vulnClasses []string, depth string) *Plan {
	var tags []string
	for _, v := range vulnClasses {
		if t, ok := vulnToNucleiTags[v]; ok {
			tags = append(tags, t...)
		}
	}

	tools := []Tool{
		{Name: "nuclei", Args: []string{"-u", target, "-tags", join(tags), "-json", "-silent"}, Timeout: 300},
		{Name: "httpx", Args: []string{"-u", target, "-silent", "-json", "-tech-detect", "-status-code"}, Timeout: 60},
	}

	if depth == "deep" {
		tools = append(tools, Tool{Name: "ffuf", Args: []string{"-u", target + "/FUZZ", "-w", "/wordlists/raft-medium.txt", "-json", "-silent"}, Timeout: 300})
	}

	return &Plan{
		Target:      target,
		VulnClasses: vulnClasses,
		Depth:       depth,
		Tools:       tools,
		NucleiTags:  tags,
	}
}

func join(s []string) string {
	r := ""
	for i, v := range s {
		if i > 0 {
			r += ","
		}
		r += v
	}
	return r
}

func (p *Plan) ToJSON() (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	return string(b), err
}