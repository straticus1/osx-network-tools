package main

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourusername/osx-network-tools/pkg/egress"
	"github.com/yourusername/osx-network-tools/pkg/patterns"
)

var (
	iface      string
	duration   int
	threshold  uint64
	outputFile string
	verbose    bool
	continuous bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "egress-auditor",
		Short: "Data exfiltration and egress auditor",
		Long:  `Monitors outbound connections and detects data exfiltration patterns`,
	}

	// Monitor command
	var monitorCmd = &cobra.Command{
		Use:   "monitor",
		Short: "Monitor outbound connections",
		Long:  `Track all outbound network connections in real-time`,
		RunE:  runMonitor,
	}
	monitorCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	monitorCmd.Flags().IntVarP(&duration, "duration", "d", 0, "Duration to monitor (seconds, 0 = unlimited)")
	monitorCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Analyze command
	var analyzeCmd = &cobra.Command{
		Use:   "analyze",
		Short: "Analyze for exfiltration patterns",
		Long:  `Monitors connections and analyzes for data exfiltration patterns`,
		RunE:  runAnalyze,
	}
	analyzeCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	analyzeCmd.Flags().IntVarP(&duration, "duration", "d", 300, "Duration to monitor (seconds)")
	analyzeCmd.Flags().Uint64VarP(&threshold, "threshold", "t", 10*1024*1024, "Large upload threshold (bytes)")
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for report")

	// Top talkers command
	var topCmd = &cobra.Command{
		Use:   "top",
		Short: "Show top data senders",
		Long:  `Display connections with highest data transfer`,
		RunE:  runTopTalkers,
	}
	topCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	topCmd.Flags().IntVarP(&duration, "duration", "d", 60, "Duration to monitor (seconds)")
	topCmd.Flags().BoolVarP(&continuous, "continuous", "c", false, "Continuous monitoring (updates every duration)")

	// Detect beaconing command
	var beaconCmd = &cobra.Command{
		Use:   "beacon",
		Short: "Detect C2 beaconing",
		Long:  `Detects periodic communication patterns indicating C2 beaconing`,
		RunE:  runBeaconDetection,
	}
	beaconCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	beaconCmd.Flags().IntVarP(&duration, "duration", "d", 300, "Duration to monitor (seconds)")

	// Report command
	var reportCmd = &cobra.Command{
		Use:   "report",
		Short: "Generate security report",
		Long:  `Generates comprehensive security report of egress traffic`,
		RunE:  runReport,
	}
	reportCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	reportCmd.Flags().IntVarP(&duration, "duration", "d", 300, "Duration to monitor (seconds)")
	reportCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for report")

	rootCmd.AddCommand(monitorCmd, analyzeCmd, topCmd, beaconCmd, reportCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runMonitor(cmd *cobra.Command, args []string) error {
	tracker := egress.NewConnectionTracker(iface)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	connectionCount := 0
	outboundCount := 0

	tracker.SetCallback(func(conn *egress.Connection) {
		connectionCount++
		if conn.IsOutbound {
			outboundCount++

			if verbose {
				fmt.Printf("[%s] %s:%d -> %s:%d (%s)\n",
					conn.StartTime.Format("15:04:05"),
					conn.SourceIP,
					conn.SourcePort,
					conn.DestIP,
					conn.DestPort,
					conn.Protocol)
			} else {
				// Non-verbose: only show new outbound connections
				fmt.Printf("→ %s:%d (%s)\n", conn.DestIP, conn.DestPort, conn.Protocol)
			}
		}
	})

	// Start monitoring in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- tracker.Start()
	}()

	// Wait for duration or signal
	if duration > 0 {
		timer := time.NewTimer(time.Duration(duration) * time.Second)
		select {
		case <-timer.C:
			fmt.Println("\nMonitoring duration completed")
		case <-sigChan:
			fmt.Println("\nMonitoring stopped by user")
		case err := <-errChan:
			return err
		}
	} else {
		select {
		case <-sigChan:
			fmt.Println("\nMonitoring stopped by user")
		case err := <-errChan:
			return err
		}
	}

	// Print summary
	printConnectionSummary(tracker)

	return nil
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	fmt.Println("Starting exfiltration analysis...")
	fmt.Printf("Interface: %s, Duration: %d seconds\n", iface, duration)
	fmt.Printf("Large upload threshold: %s\n\n", egress.FormatBytes(threshold))

	tracker := egress.NewConnectionTracker(iface)
	detector := patterns.NewExfiltrationDetector()

	// Set custom threshold
	thresholds := patterns.DetectionThresholds{
		LargeUploadBytes:      threshold,
		LargeUploadDuration:   300,
		UnusualPortConnections: 5,
		HighEntropyThreshold:  0.75,
		DNSTunnelQueriesMin:   10,
		BeaconingJitterMax:    5.0,
	}
	detector.SetThresholds(thresholds)

	// Track patterns as they're detected
	detectedPatterns := 0

	tracker.SetCallback(func(conn *egress.Connection) {
		if !conn.IsOutbound {
			return
		}

		// Analyze connection
		patterns := detector.AnalyzeConnection(conn)
		if len(patterns) > 0 {
			detectedPatterns += len(patterns)
			for _, pattern := range patterns {
				printPattern(pattern)
			}
		}
	})

	// Start monitoring
	go tracker.Start()

	// Monitor for specified duration
	time.Sleep(time.Duration(duration) * time.Second)

	// Generate final report
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("EXFILTRATION ANALYSIS REPORT")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	stats := tracker.GetConnectionStatistics()
	printAnalysisReport(stats, detector, detectedPatterns)

	// Check for beaconing
	connections := tracker.GetOutboundConnections()
	beaconPatterns := detector.DetectBeaconing(connections)

	if len(beaconPatterns) > 0 {
		fmt.Println("\n⚠️  BEACONING DETECTED:")
		for _, pattern := range beaconPatterns {
			printPattern(pattern)
		}
	}

	return nil
}

func runTopTalkers(cmd *cobra.Command, args []string) error {
	tracker := egress.NewConnectionTracker(iface)

	go tracker.Start()

	for {
		time.Sleep(time.Duration(duration) * time.Second)

		// Clear screen (simple approach)
		fmt.Print("\033[H\033[2J")

		fmt.Println("TOP DATA SENDERS")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("Updated: %s\n\n", time.Now().Format("15:04:05"))

		topTalkers := tracker.GetTopTalkers(10)

		fmt.Printf("%-15s %-6s %-15s %-6s %-12s %-12s\n",
			"SOURCE", "PORT", "DEST", "PORT", "SENT", "RECEIVED")
		fmt.Println(strings.Repeat("-", 80))

		for _, conn := range topTalkers {
			fmt.Printf("%-15s %-6d %-15s %-6d %-12s %-12s\n",
				conn.SourceIP,
				conn.SourcePort,
				conn.DestIP,
				conn.DestPort,
				egress.FormatBytes(conn.BytesSent),
				egress.FormatBytes(conn.BytesRecv))
		}

		if !continuous {
			break
		}
	}

	return nil
}

func runBeaconDetection(cmd *cobra.Command, args []string) error {
	fmt.Println("Detecting C2 beaconing patterns...")
	fmt.Printf("Monitoring for %d seconds...\n\n", duration)

	tracker := egress.NewConnectionTracker(iface)
	detector := patterns.NewExfiltrationDetector()

	go tracker.Start()

	time.Sleep(time.Duration(duration) * time.Second)

	// Analyze for beaconing
	connections := tracker.GetOutboundConnections()
	beaconPatterns := detector.DetectBeaconing(connections)

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("BEACONING DETECTION REPORT")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	if len(beaconPatterns) == 0 {
		fmt.Println("✓ No beaconing patterns detected")
		return nil
	}

	fmt.Printf("⚠️  Found %d potential beaconing patterns:\n\n", len(beaconPatterns))

	for i, pattern := range beaconPatterns {
		fmt.Printf("%d. %s\n", i+1, pattern.Description)
		fmt.Printf("   Severity: %s (Confidence: %.0f%%)\n", pattern.Severity, pattern.Confidence*100)
		fmt.Printf("   Indicators:\n")
		for _, indicator := range pattern.Indicators {
			fmt.Printf("     - %s\n", indicator)
		}
		fmt.Println()
	}

	return nil
}

func runReport(cmd *cobra.Command, args []string) error {
	fmt.Println("Generating security report...")
	fmt.Printf("Monitoring for %d seconds...\n\n", duration)

	tracker := egress.NewConnectionTracker(iface)
	detector := patterns.NewExfiltrationDetector()

	// Analyze connections
	tracker.SetCallback(func(conn *egress.Connection) {
		if conn.IsOutbound {
			detector.AnalyzeConnection(conn)
		}
	})

	go tracker.Start()
	time.Sleep(time.Duration(duration) * time.Second)

	// Generate comprehensive report
	report := generateSecurityReport(tracker, detector)

	// Print to console
	fmt.Println(report)

	// Save to file if specified
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf("\n✓ Report saved to: %s\n", outputFile)
	}

	return nil
}

func printConnectionSummary(tracker *egress.ConnectionTracker) {
	stats := tracker.GetConnectionStatistics()

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("CONNECTION SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	fmt.Printf("Total Connections: %d\n", stats.TotalConnections)
	fmt.Printf("  Outbound: %d\n", stats.OutboundConnections)
	fmt.Printf("  Inbound: %d\n", stats.InboundConnections)
	fmt.Println()

	fmt.Printf("Data Transfer:\n")
	fmt.Printf("  Sent: %s\n", egress.FormatBytes(stats.TotalBytesSent))
	fmt.Printf("  Received: %s\n", egress.FormatBytes(stats.TotalBytesRecv))
	fmt.Println()

	fmt.Println("By Protocol:")
	for proto, count := range stats.ByProtocol {
		fmt.Printf("  %s: %d\n", proto, count)
	}

	if len(stats.ByPort) > 0 {
		fmt.Println("\nTop Ports:")

		// Sort ports by connection count
		type portCount struct {
			port  uint16
			count int
		}
		ports := make([]portCount, 0, len(stats.ByPort))
		for port, count := range stats.ByPort {
			ports = append(ports, portCount{port, count})
		}
		sort.Slice(ports, func(i, j int) bool {
			return ports[i].count > ports[j].count
		})

		// Show top 10
		for i, pc := range ports {
			if i >= 10 {
				break
			}
			fmt.Printf("  %d: %d connections\n", pc.port, pc.count)
		}
	}
}

func printPattern(pattern *patterns.ExfiltrationPattern) {
	severitySymbol := "⚠️"
	if pattern.Severity == "CRITICAL" {
		severitySymbol = "🚨"
	} else if pattern.Severity == "HIGH" {
		severitySymbol = "❌"
	}

	fmt.Printf("\n%s [%s] %s\n", severitySymbol, pattern.Severity, pattern.Description)
	fmt.Printf("   Confidence: %.0f%%\n", pattern.Confidence*100)
	fmt.Printf("   Time: %s\n", pattern.Timestamp.Format("15:04:05"))

	if pattern.Connection != nil {
		fmt.Printf("   Connection: %s:%d -> %s:%d\n",
			pattern.Connection.SourceIP,
			pattern.Connection.SourcePort,
			pattern.Connection.DestIP,
			pattern.Connection.DestPort)
	}

	if len(pattern.Indicators) > 0 {
		fmt.Println("   Indicators:")
		for _, indicator := range pattern.Indicators {
			fmt.Printf("     - %s\n", indicator)
		}
	}
}

func printAnalysisReport(stats *egress.ConnectionStats, detector *patterns.ExfiltrationDetector, detectedCount int) {
	fmt.Printf("Connections Analyzed: %d\n", stats.OutboundConnections)
	fmt.Printf("Total Data Sent: %s\n", egress.FormatBytes(stats.TotalBytesSent))
	fmt.Printf("Patterns Detected: %d\n", detectedCount)
	fmt.Println()

	// Count by severity
	critical := len(detector.GetPatternsBySeverity("CRITICAL"))
	high := len(detector.GetPatternsBySeverity("HIGH"))
	medium := len(detector.GetPatternsBySeverity("MEDIUM"))

	fmt.Println("By Severity:")
	if critical > 0 {
		fmt.Printf("  🚨 CRITICAL: %d\n", critical)
	}
	if high > 0 {
		fmt.Printf("  ❌ HIGH: %d\n", high)
	}
	if medium > 0 {
		fmt.Printf("  ⚠️  MEDIUM: %d\n", medium)
	}

	if critical == 0 && high == 0 && medium == 0 {
		fmt.Println("  ✓ No significant threats detected")
	}
}

func generateSecurityReport(tracker *egress.ConnectionTracker, detector *patterns.ExfiltrationDetector) string {
	var report strings.Builder

	report.WriteString(strings.Repeat("=", 80) + "\n")
	report.WriteString("EGRESS SECURITY REPORT\n")
	report.WriteString(strings.Repeat("=", 80) + "\n")
	report.WriteString(fmt.Sprintf("\nGenerated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Connection statistics
	stats := tracker.GetConnectionStatistics()
	report.WriteString("CONNECTION STATISTICS:\n")
	report.WriteString(fmt.Sprintf("  Total Connections: %d\n", stats.TotalConnections))
	report.WriteString(fmt.Sprintf("  Outbound: %d\n", stats.OutboundConnections))
	report.WriteString(fmt.Sprintf("  Data Sent: %s\n", egress.FormatBytes(stats.TotalBytesSent)))
	report.WriteString(fmt.Sprintf("  Data Received: %s\n\n", egress.FormatBytes(stats.TotalBytesRecv)))

	// Detected patterns
	patterns := detector.GetPatterns()
	report.WriteString(fmt.Sprintf("SECURITY FINDINGS: %d patterns detected\n\n", len(patterns)))

	if len(patterns) > 0 {
		critical := detector.GetPatternsBySeverity("CRITICAL")
		high := detector.GetPatternsBySeverity("HIGH")
		medium := detector.GetPatternsBySeverity("MEDIUM")

		if len(critical) > 0 {
			report.WriteString(fmt.Sprintf("CRITICAL THREATS: %d\n", len(critical)))
			for _, p := range critical {
				report.WriteString(fmt.Sprintf("  - %s\n", p.Description))
			}
			report.WriteString("\n")
		}

		if len(high) > 0 {
			report.WriteString(fmt.Sprintf("HIGH SEVERITY: %d\n", len(high)))
			for _, p := range high {
				report.WriteString(fmt.Sprintf("  - %s\n", p.Description))
			}
			report.WriteString("\n")
		}

		if len(medium) > 0 {
			report.WriteString(fmt.Sprintf("MEDIUM SEVERITY: %d\n", len(medium)))
			for _, p := range medium {
				report.WriteString(fmt.Sprintf("  - %s\n", p.Description))
			}
			report.WriteString("\n")
		}
	} else {
		report.WriteString("✓ No significant security threats detected\n\n")
	}

	// Top data senders
	topTalkers := tracker.GetTopTalkers(5)
	if len(topTalkers) > 0 {
		report.WriteString("TOP DATA SENDERS:\n")
		for i, conn := range topTalkers {
			report.WriteString(fmt.Sprintf("  %d. %s:%d (%s sent)\n",
				i+1, conn.DestIP, conn.DestPort, egress.FormatBytes(conn.BytesSent)))
		}
		report.WriteString("\n")
	}

	// Recommendations
	report.WriteString("RECOMMENDATIONS:\n")
	if stats.SuspiciousCount > 0 {
		report.WriteString("  - Investigate suspicious connections immediately\n")
	}
	if len(detector.GetPatternsBySeverity("CRITICAL")) > 0 {
		report.WriteString("  - Critical threats detected - immediate action required\n")
	}
	report.WriteString("  - Review firewall rules for outbound connections\n")
	report.WriteString("  - Implement data loss prevention (DLP) policies\n")
	report.WriteString("  - Enable enhanced logging for high-risk connections\n")

	report.WriteString("\n" + strings.Repeat("=", 80) + "\n")

	return report.String()
}
