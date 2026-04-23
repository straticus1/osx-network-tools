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
	"github.com/yourusername/osx-network-tools/pkg/discovery"
)

var (
	iface      string
	configFile string
	duration   int
	outputFile string
	verbose    bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "shadow-detector",
		Short: "Shadow IT detection tool",
		Long:  `Detects unauthorized services, cloud applications, and Shadow IT on your network`,
	}

	// DNS monitoring command
	var dnsCmd = &cobra.Command{
		Use:   "dns",
		Short: "Monitor DNS queries",
		Long:  `Captures and analyzes DNS queries to identify unauthorized services`,
		RunE:  runDNSMonitor,
	}
	dnsCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	dnsCmd.Flags().IntVarP(&duration, "duration", "d", 0, "Duration to monitor (seconds, 0 = unlimited)")
	dnsCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// TLS/SNI monitoring command
	var tlsCmd = &cobra.Command{
		Use:   "tls",
		Short: "Monitor TLS/HTTPS connections",
		Long:  `Extracts SNI from TLS handshakes to identify HTTPS services`,
		RunE:  runTLSMonitor,
	}
	tlsCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	tlsCmd.Flags().IntVarP(&duration, "duration", "d", 0, "Duration to monitor (seconds, 0 = unlimited)")
	tlsCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Full scan command
	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Full network scan",
		Long:  `Performs comprehensive scan of DNS and TLS traffic`,
		RunE:  runFullScan,
	}
	scanCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	scanCmd.Flags().IntVarP(&duration, "duration", "d", 60, "Duration to monitor (seconds)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for report")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Cloud services command
	var cloudCmd = &cobra.Command{
		Use:   "cloud",
		Short: "Detect cloud services",
		Long:  `Identifies cloud service usage from network traffic`,
		RunE:  runCloudDetection,
	}
	cloudCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	cloudCmd.Flags().IntVarP(&duration, "duration", "d", 60, "Duration to monitor (seconds)")

	rootCmd.AddCommand(dnsCmd, tlsCmd, scanCmd, cloudCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runDNSMonitor(cmd *cobra.Command, args []string) error {
	monitor := discovery.NewDNSMonitor(iface)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Track statistics
	queryCount := 0
	suspiciousCount := 0
	cloudServices := make(map[string]bool)

	monitor.SetCallback(func(query *discovery.DNSQuery) {
		queryCount++

		if verbose {
			fmt.Printf("[%s] %s -> %s (%s)\n",
				query.Timestamp.Format("15:04:05"),
				query.SourceIP,
				query.QueryName,
				query.QueryType)
		}

		// Check for suspicious queries
		if monitor.IsSuspiciousDomain(query.QueryName) {
			suspiciousCount++
			fmt.Printf("⚠️  SUSPICIOUS: %s from %s\n", query.QueryName, query.SourceIP)
		}

		// Check for cloud services
		if service := monitor.IdentifyCloudService(query.QueryName); service != nil {
			key := service.Provider + ":" + service.ServiceName
			if !cloudServices[key] {
				cloudServices[key] = true
				fmt.Printf("☁️  CLOUD SERVICE: %s - %s (%s)\n",
					service.Provider,
					service.ServiceName,
					query.QueryName)
			}
		}
	})

	// Start monitoring in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- monitor.Start()
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
	printDNSSummary(queryCount, suspiciousCount, cloudServices)

	return nil
}

func runTLSMonitor(cmd *cobra.Command, args []string) error {
	extractor := discovery.NewSNIExtractor(iface)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	connectionCount := 0
	services := make(map[string]int)

	extractor.SetCallback(func(conn *discovery.TLSConnection) {
		connectionCount++

		if verbose {
			fmt.Printf("[%s] %s -> %s:%d | SNI: %s | TLS: %s\n",
				conn.Timestamp.Format("15:04:05"),
				conn.SourceIP,
				conn.DestIP,
				conn.DestPort,
				conn.ServerName,
				conn.TLSVersion)
		}

		// Identify service
		if conn.ServerName != "" {
			service := extractor.IdentifyService(conn.ServerName)
			services[service]++

			if service != "Unknown" {
				fmt.Printf("🔒 TLS Connection: %s (%s)\n", conn.ServerName, service)
			}
		}
	})

	// Start monitoring in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- extractor.Start()
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
	printTLSSummary(connectionCount, services, extractor)

	return nil
}

func runFullScan(cmd *cobra.Command, args []string) error {
	fmt.Println("Starting full network scan...")
	fmt.Printf("Interface: %s\n", iface)
	fmt.Printf("Duration: %d seconds\n", duration)
	fmt.Println()

	// Start DNS monitor
	dnsMonitor := discovery.NewDNSMonitor(iface)
	dnsQueries := 0
	suspiciousDomains := []string{}

	dnsMonitor.SetCallback(func(query *discovery.DNSQuery) {
		dnsQueries++
		if dnsMonitor.IsSuspiciousDomain(query.QueryName) {
			suspiciousDomains = append(suspiciousDomains, query.QueryName)
		}
	})

	// Start TLS monitor
	tlsExtractor := discovery.NewSNIExtractor(iface)
	tlsConnections := 0

	tlsExtractor.SetCallback(func(conn *discovery.TLSConnection) {
		tlsConnections++
	})

	// Start both monitors
	go dnsMonitor.Start()
	go tlsExtractor.Start()

	// Wait for duration
	time.Sleep(time.Duration(duration) * time.Second)

	// Generate report
	generateReport(dnsMonitor, tlsExtractor, dnsQueries, tlsConnections, suspiciousDomains)

	return nil
}

func runCloudDetection(cmd *cobra.Command, args []string) error {
	fmt.Println("Detecting cloud services...")
	fmt.Printf("Monitoring for %d seconds...\n\n", duration)

	monitor := discovery.NewDNSMonitor(iface)

	go monitor.Start()

	time.Sleep(time.Duration(duration) * time.Second)

	// Extract cloud services
	services := monitor.ExtractCloudServices()

	// Print results
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println("CLOUD SERVICES DETECTED")
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println()

	if len(services) == 0 {
		fmt.Println("No cloud services detected")
		return nil
	}

	// Group by provider
	byProvider := make(map[string][]discovery.CloudService)
	for _, service := range services {
		byProvider[service.Provider] = append(byProvider[service.Provider], service)
	}

	for provider, providerServices := range byProvider {
		fmt.Printf("\n%s:\n", provider)
		for _, service := range providerServices {
			fmt.Printf("  - %s\n", service.ServiceName)
			fmt.Printf("    Domain: %s\n", service.Domain)
			fmt.Printf("    Access Count: %d\n", service.AccessCount)
			fmt.Printf("    First Seen: %s\n", service.FirstSeen.Format("15:04:05"))
			fmt.Printf("    Last Seen: %s\n", service.LastSeen.Format("15:04:05"))
			fmt.Println()
		}
	}

	return nil
}

func printDNSSummary(total, suspicious int, cloudServices map[string]bool) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("DNS MONITORING SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\nTotal Queries: %d\n", total)
	fmt.Printf("Suspicious Queries: %d\n", suspicious)
	fmt.Printf("Cloud Services Detected: %d\n", len(cloudServices))

	if len(cloudServices) > 0 {
		fmt.Println("\nCloud Services:")
		for service := range cloudServices {
			fmt.Printf("  - %s\n", service)
		}
	}
}

func printTLSSummary(total int, services map[string]int, extractor *discovery.SNIExtractor) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("TLS MONITORING SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\nTotal Connections: %d\n", total)
	fmt.Printf("Unique Hosts: %d\n", len(extractor.GetUniqueHosts()))

	if len(services) > 0 {
		fmt.Println("\nServices Detected:")

		// Sort by count
		type serviceStat struct {
			name  string
			count int
		}
		stats := make([]serviceStat, 0, len(services))
		for name, count := range services {
			stats = append(stats, serviceStat{name, count})
		}
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].count > stats[j].count
		})

		for _, stat := range stats {
			fmt.Printf("  - %s: %d connections\n", stat.name, stat.count)
		}
	}
}

func generateReport(dnsMonitor *discovery.DNSMonitor, tlsExtractor *discovery.SNIExtractor,
	dnsQueries, tlsConnections int, suspiciousDomains []string) {

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("SHADOW IT DETECTION REPORT")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\nGenerated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// DNS Summary
	fmt.Println("DNS Activity:")
	fmt.Printf("  Total Queries: %d\n", dnsQueries)
	fmt.Printf("  Suspicious Domains: %d\n", len(suspiciousDomains))

	if len(suspiciousDomains) > 0 {
		fmt.Println("\n  Suspicious Domains:")
		for i, domain := range suspiciousDomains {
			if i < 10 { // Limit to first 10
				fmt.Printf("    - %s\n", domain)
			}
		}
		if len(suspiciousDomains) > 10 {
			fmt.Printf("    ... and %d more\n", len(suspiciousDomains)-10)
		}
	}

	// TLS Summary
	fmt.Println("\nTLS Activity:")
	fmt.Printf("  Total Connections: %d\n", tlsConnections)
	fmt.Printf("  Unique Hosts: %d\n", len(tlsExtractor.GetUniqueHosts()))

	// Cloud Services
	cloudServices := dnsMonitor.ExtractCloudServices()
	fmt.Printf("\nCloud Services: %d\n", len(cloudServices))

	if len(cloudServices) > 0 {
		byProvider := make(map[string]int)
		for _, service := range cloudServices {
			byProvider[service.Provider]++
		}

		fmt.Println("  By Provider:")
		for provider, count := range byProvider {
			fmt.Printf("    - %s: %d services\n", provider, count)
		}
	}

	// Service Statistics
	stats := tlsExtractor.GetServiceStatistics()
	if len(stats) > 0 {
		fmt.Println("\nService Usage:")
		for service, count := range stats {
			if service != "Unknown" {
				fmt.Printf("  - %s: %d connections\n", service, count)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}
