package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zxchx/recon/internal/planner"
	"github.com/zxchx/recon/internal/executor"
	"github.com/zxchx/recon/internal/correlator"
	"github.com/zxchx/recon/internal/reporter"
)

var rootCmd = &cobra.Command{
	Use:   "recon",
	Short: "RECON - Rapid Exploit Confirmation & Offensive Recon",
	Long:  `Automated bug bounty assistant: plan → execute → correlate → report.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan target for vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		vulnClasses, _ := cmd.Flags().GetStringSlice("vuln")
		depth, _ := cmd.Flags().GetString("depth")

		fmt.Printf("[RECON] Scanning %s (vuln: %v, depth: %s)\n", target, vulnClasses, depth)

		// 1. PLANNER
		plan := planner.GeneratePlan(target, vulnClasses, depth)
		fmt.Println("[PLAN] Generated execution plan")

		// 2. EXECUTOR
		findings := executor.Execute(plan)
		fmt.Printf("[EXEC] Found %d raw findings\n", len(findings))

		// 3. CORRELATOR
		correlated := correlator.Correlate(findings)
		fmt.Printf("[CORRELATE] Deduped to %d prioritized findings\n", len(correlated))

		// 4. REPORTER
		report := reporter.Generate(correlated, target)
		reporter.Save(report, target)
		fmt.Println("[REPORT] Saved to ./output/")
	},
}

func init() {
	scanCmd.Flags().StringSliceP("vuln", "v", []string{"xss", "sqli", "ssrf", "idor", "auth-bypass"}, "Vulnerability classes to scan")
	scanCmd.Flags().StringP("depth", "d", "normal", "Scan depth: quick, normal, deep")
	rootCmd.AddCommand(scanCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}