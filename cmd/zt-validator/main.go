package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourusername/osx-network-tools/pkg/mtls"
)

var (
	certFile   string
	keyFile    string
	caFile     string
	iface      string
	configFile string
	verbose    bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "zt-validator",
		Short: "Zero Trust certificate validator and monitor",
		Long:  `A tool for validating mTLS certificates and monitoring TLS connections for zero trust security.`,
	}

	// Validate certificate command
	var validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate a certificate file",
		Long:  `Validates an X.509 certificate against security policies`,
		RunE:  runValidate,
	}
	validateCmd.Flags().StringVarP(&certFile, "cert", "c", "", "Certificate file to validate (required)")
	validateCmd.Flags().StringVar(&caFile, "ca", "", "CA certificate file for chain validation")
	validateCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	validateCmd.MarkFlagRequired("cert")

	// Monitor command
	var monitorCmd = &cobra.Command{
		Use:   "monitor",
		Short: "Monitor TLS connections",
		Long:  `Captures and validates TLS handshakes in real-time`,
		RunE:  runMonitor,
	}
	monitorCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "Network interface to monitor")
	monitorCmd.Flags().StringVarP(&configFile, "config", "f", "configs/mtls-policies.yaml", "Policy configuration file")
	monitorCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Check OCSP command
	var ocspCmd = &cobra.Command{
		Use:   "ocsp",
		Short: "Check OCSP status",
		Long:  `Checks the OCSP revocation status of a certificate`,
		RunE:  runOCSP,
	}
	ocspCmd.Flags().StringVarP(&certFile, "cert", "c", "", "Certificate file to check (required)")
	ocspCmd.Flags().StringVar(&caFile, "issuer", "", "Issuer certificate file")
	ocspCmd.MarkFlagRequired("cert")

	// Info command
	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Display certificate information",
		Long:  `Shows detailed information about a certificate`,
		RunE:  runInfo,
	}
	infoCmd.Flags().StringVarP(&certFile, "cert", "c", "", "Certificate file to inspect (required)")
	infoCmd.MarkFlagRequired("cert")

	rootCmd.AddCommand(validateCmd, monitorCmd, ocspCmd, infoCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runValidate(cmd *cobra.Command, args []string) error {
	validator := mtls.NewValidator(mtls.DefaultPolicies())

	result, err := validator.ValidateCertFile(certFile)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	printValidationResult(result)
	return nil
}

func runMonitor(cmd *cobra.Command, args []string) error {
	fmt.Printf("Monitoring TLS connections on interface: %s\n", iface)
	fmt.Println("Press Ctrl+C to stop...")

	validator := mtls.NewValidator(mtls.DefaultPolicies())

	if err := validator.MonitorTLSConnections(iface); err != nil {
		return fmt.Errorf("monitoring failed: %w", err)
	}

	return nil
}

func runOCSP(cmd *cobra.Command, args []string) error {
	validator := mtls.NewValidator(mtls.DefaultPolicies())

	result, err := validator.ValidateCertFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	if len(result.Info.OCSPServer) == 0 {
		fmt.Println("Certificate has no OCSP responder")
		return nil
	}

	fmt.Printf("OCSP Server: %s\n", result.Info.OCSPServer[0])
	fmt.Println("Note: Full OCSP checking requires issuer certificate")

	return nil
}

func runInfo(cmd *cobra.Command, args []string) error {
	validator := mtls.NewValidator(mtls.DefaultPolicies())

	result, err := validator.ValidateCertFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	printCertificateInfo(result.Info)
	return nil
}

func printValidationResult(result *mtls.ValidationResult) {
	if result.Valid {
		fmt.Println("✓ Certificate is VALID")
	} else {
		fmt.Println("✗ Certificate is INVALID")
	}
	fmt.Println()

	if len(result.Errors) > 0 {
		fmt.Println("Errors:")
		for _, err := range result.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warn := range result.Warnings {
			fmt.Printf("  ⚠ %s\n", warn)
		}
		fmt.Println()
	}

	fmt.Println("Certificate Details:")
	printCertificateInfo(result.Info)

	if result.ChainValid {
		fmt.Printf("\n✓ Certificate chain is valid (%d certificates in chain)\n", len(result.ChainCerts)+1)
	} else if !result.Info.IsSelfSigned {
		fmt.Println("\n✗ Certificate chain validation failed")
	}
}

func printCertificateInfo(info *mtls.CertificateInfo) {
	fmt.Printf("  Subject: %s\n", info.Subject)
	fmt.Printf("  Issuer: %s\n", info.Issuer)
	fmt.Printf("  Serial: %s\n", info.SerialNumber)
	fmt.Printf("  Valid From: %s\n", info.NotBefore.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  Valid Until: %s\n", info.NotAfter.Format("2006-01-02 15:04:05 MST"))

	if info.IsExpired {
		fmt.Println("  Status: EXPIRED")
	} else if info.DaysUntilExpiry < 30 {
		fmt.Printf("  Status: Expires in %d days (WARNING)\n", info.DaysUntilExpiry)
	} else {
		fmt.Printf("  Status: Valid (%d days remaining)\n", info.DaysUntilExpiry)
	}

	if info.IsSelfSigned {
		fmt.Println("  Type: Self-Signed")
	}
	if info.IsCA {
		fmt.Println("  Type: Certificate Authority")
	}

	fmt.Printf("  Signature Algorithm: %s\n", info.SignatureAlgorithm)
	fmt.Printf("  Public Key Algorithm: %s\n", info.PublicKeyAlgorithm)

	if len(info.DNSNames) > 0 {
		fmt.Println("  DNS Names:")
		for _, dns := range info.DNSNames {
			fmt.Printf("    - %s\n", dns)
		}
	}

	if len(info.IPAddresses) > 0 {
		fmt.Println("  IP Addresses:")
		for _, ip := range info.IPAddresses {
			fmt.Printf("    - %s\n", ip)
		}
	}

	if len(info.KeyUsage) > 0 {
		fmt.Printf("  Key Usage: %v\n", info.KeyUsage)
	}

	if len(info.ExtKeyUsage) > 0 {
		fmt.Printf("  Extended Key Usage: %v\n", info.ExtKeyUsage)
	}

	if len(info.OCSPServer) > 0 {
		fmt.Printf("  OCSP Server: %s\n", info.OCSPServer[0])
	}

	if len(info.CRLDistribution) > 0 {
		fmt.Printf("  CRL Distribution: %s\n", info.CRLDistribution[0])
	}
}
