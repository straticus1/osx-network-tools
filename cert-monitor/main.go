package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type CertInfo struct {
	Host       string
	CommonName string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	DaysLeft   int
	IsValid    bool
	Error      string
}

func main() {
	host := flag.String("host", "", "Host to check (e.g., google.com)")
	port := flag.Int("port", 443, "Port to connect to")
	hostsFile := flag.String("hosts-file", "", "File containing list of hosts (one per line)")
	warnDays := flag.Int("warn-days", 30, "Warn if certificate expires within this many days")

	flag.Parse()

	if *host == "" && *hostsFile == "" {
		fmt.Fprintln(os.Stderr, "Error: Must provide either -host or -hosts-file")
		flag.Usage()
		os.Exit(1)
	}

	var hosts []string
	if *hostsFile != "" {
		var err error
		hosts, err = readHostsFile(*hostsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading hosts file: %v\n", err)
			os.Exit(1)
		}
	} else {
		hosts = []string{*host}
	}

	fmt.Println("🔐 Certificate Monitor")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	expiringSoon := []CertInfo{}
	expired := []CertInfo{}
	healthy := []CertInfo{}

	for _, h := range hosts {
		info := checkCertificate(h, *port)
		
		if info.Error != "" {
			fmt.Printf("❌ %s\n", info.Host)
			fmt.Printf("   Error: %s\n\n", info.Error)
			continue
		}

		fmt.Printf("📜 %s\n", info.Host)
		fmt.Printf("   Common Name: %s\n", info.CommonName)
		fmt.Printf("   Issuer: %s\n", info.Issuer)
		fmt.Printf("   Valid From: %s\n", info.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Valid Until: %s\n", info.NotAfter.Format("2006-01-02 15:04:05"))

		if info.DaysLeft < 0 {
			fmt.Printf("   Status: ⛔️ EXPIRED (%d days ago)\n", -info.DaysLeft)
			expired = append(expired, info)
		} else if info.DaysLeft <= *warnDays {
			fmt.Printf("   Status: ⚠️  EXPIRING SOON (%d days left)\n", info.DaysLeft)
			expiringSoon = append(expiringSoon, info)
		} else {
			fmt.Printf("   Status: ✅ Valid (%d days left)\n", info.DaysLeft)
			healthy = append(healthy, info)
		}
		fmt.Println()
	}

	// Summary
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Summary: %d healthy, %d expiring soon, %d expired\n", 
		len(healthy), len(expiringSoon), len(expired))

	if len(expiringSoon) > 0 {
		fmt.Printf("\n⚠️  Certificates expiring within %d days:\n", *warnDays)
		for _, cert := range expiringSoon {
			fmt.Printf("   - %s (%d days)\n", cert.Host, cert.DaysLeft)
		}
	}

	if len(expired) > 0 {
		fmt.Println("\n⛔️ Expired certificates:")
		for _, cert := range expired {
			fmt.Printf("   - %s (expired %d days ago)\n", cert.Host, -cert.DaysLeft)
		}
	}
}

func checkCertificate(host string, port int) CertInfo {
	info := CertInfo{
		Host: host,
	}

	// Add default port if not specified
	addr := host
	if !strings.Contains(host, ":") {
		addr = fmt.Sprintf("%s:%d", host, port)
	}

	// Configure TLS with proper verification; VerifyPeerCertificate allows custom checks
	// (e.g., expiry warnings) while standard chain validation remains active.
	conf := &tls.Config{
		ServerName: host,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Custom checks (e.g., expiry warnings) can go here — chain already validated by TLS.
			return nil
		},
	}

	// Set connection timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		info.Error = "No certificates found"
		return info
	}

	// Get the first certificate (leaf certificate)
	cert := certs[0]

	info.CommonName = cert.Subject.CommonName
	info.Issuer = cert.Issuer.CommonName
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	
	now := time.Now()
	if now.Before(cert.NotBefore) {
		info.IsValid = false
		info.Error = "Certificate not yet valid"
	} else if now.After(cert.NotAfter) {
		info.IsValid = false
		info.DaysLeft = -int(now.Sub(cert.NotAfter).Hours() / 24)
	} else {
		info.IsValid = true
		info.DaysLeft = int(cert.NotAfter.Sub(now).Hours() / 24)
	}

	return info
}

func readHostsFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	hosts := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}

	return hosts, nil
}
