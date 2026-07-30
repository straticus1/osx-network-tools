package mtls

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CertificateInfo holds certificate validation results
type CertificateInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	IsExpired          bool
	DaysUntilExpiry    int
	IsCA               bool
	IsSelfSigned       bool
	KeyUsage           []string
	ExtKeyUsage        []string
	DNSNames           []string
	IPAddresses        []string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	Version            int
	OCSPServer         []string
	CRLDistribution    []string
}

// ValidationResult contains the outcome of certificate validation
type ValidationResult struct {
	Valid      bool
	Errors     []string
	Warnings   []string
	Info       *CertificateInfo
	ChainValid bool
	ChainCerts []*CertificateInfo
}

// Validator handles certificate validation operations
type Validator struct {
	RootCAs   *x509.CertPool
	Policies  *ValidationPolicies
	PinnedFPs map[string]string // hostname -> fingerprint
}

// ValidationPolicies defines certificate validation rules
type ValidationPolicies struct {
	MinKeySize           int
	MaxCertAge           time.Duration
	RequireOCSP          bool
	AllowSelfSigned      bool
	RequiredKeyUsages    []x509.KeyUsage
	RequiredExtKeyUsages []x509.ExtKeyUsage
	BlockedIssuers       []string
	ExpiryWarningDays    int
}

// NewValidator creates a new certificate validator
func NewValidator(policies *ValidationPolicies) *Validator {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	return &Validator{
		RootCAs:   rootCAs,
		Policies:  policies,
		PinnedFPs: make(map[string]string),
	}
}

// DefaultPolicies returns sensible default validation policies
func DefaultPolicies() *ValidationPolicies {
	return &ValidationPolicies{
		MinKeySize:        2048,
		MaxCertAge:        825 * 24 * time.Hour, // 825 days (Apple/Google limit)
		RequireOCSP:       true,
		AllowSelfSigned:   false,
		ExpiryWarningDays: 30,
		RequiredKeyUsages: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
		},
	}
}

// ValidateCertFile validates a certificate from a PEM file
func (v *Validator) ValidateCertFile(certPath string) (*ValidationResult, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return v.ValidateCertificate(cert, nil), nil
}

// ValidateCertificate validates an x509 certificate against policies
func (v *Validator) ValidateCertificate(cert *x509.Certificate, intermediates []*x509.Certificate) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		Info:     extractCertInfo(cert),
	}

	// Check expiration
	now := time.Now()
	if cert.NotAfter.Before(now) {
		result.Valid = false
		result.Errors = append(result.Errors, "Certificate has expired")
	} else if cert.NotAfter.Sub(now) < time.Duration(v.Policies.ExpiryWarningDays)*24*time.Hour {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Certificate expires in %d days", int(cert.NotAfter.Sub(now).Hours()/24)))
	}

	if cert.NotBefore.After(now) {
		result.Valid = false
		result.Errors = append(result.Errors, "Certificate is not yet valid")
	}

	// Check key size
	if keySize := getKeySize(cert); keySize > 0 && keySize < v.Policies.MinKeySize {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Key size %d is below minimum %d", keySize, v.Policies.MinKeySize))
	}

	// Check certificate age (validity period)
	certAge := cert.NotAfter.Sub(cert.NotBefore)
	if certAge > v.Policies.MaxCertAge {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Certificate validity period (%d days) exceeds recommended maximum", int(certAge.Hours()/24)))
	}

	// Check self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		result.Info.IsSelfSigned = true
		if !v.Policies.AllowSelfSigned {
			result.Valid = false
			result.Errors = append(result.Errors, "Self-signed certificates are not allowed")
		}
	}

	// Check OCSP. A required revocation check is fail-closed: an unavailable
	// responder, missing issuer, unknown status, or invalid response is not a
	// valid certificate result.
	if v.Policies.RequireOCSP {
		if len(cert.OCSPServer) == 0 {
			result.Valid = false
			result.Errors = append(result.Errors, "Certificate has no OCSP responder")
		} else if len(intermediates) == 0 {
			result.Valid = false
			result.Errors = append(result.Errors, "OCSP issuer certificate is required")
		} else if status, err := v.CheckOCSPStatus(cert, intermediates[0]); err != nil || status != "good" {
			result.Valid = false
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("OCSP validation failed: %v", err))
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("OCSP status is %s", status))
			}
		}
	}

	// Validate certificate chain
	if !result.Info.IsSelfSigned {
		chainValid := v.validateChain(cert, intermediates, result)
		result.ChainValid = chainValid
		if !chainValid {
			result.Valid = false
		}
	}

	// Check blocked issuers
	for _, blocked := range v.Policies.BlockedIssuers {
		if cert.Issuer.String() == blocked {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Certificate issued by blocked issuer: %s", blocked))
		}
	}

	return result
}

// validateChain validates the certificate chain
func (v *Validator) validateChain(cert *x509.Certificate, intermediates []*x509.Certificate, result *ValidationResult) bool {
	opts := x509.VerifyOptions{
		Roots:         v.RootCAs,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
	}

	for _, intermediate := range intermediates {
		opts.Intermediates.AddCert(intermediate)
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Chain validation failed: %v", err))
		return false
	}

	// Extract chain information
	if len(chains) > 0 {
		for _, chainCert := range chains[0] {
			if chainCert.Equal(cert) {
				continue
			}
			result.ChainCerts = append(result.ChainCerts, extractCertInfo(chainCert))
		}
	}

	return true
}

// CheckOCSPStatus checks the OCSP status of a certificate
func (v *Validator) CheckOCSPStatus(cert *x509.Certificate, issuer *x509.Certificate) (string, error) {
	if issuer == nil {
		return "error", fmt.Errorf("issuer certificate is required")
	}
	if len(cert.OCSPServer) == 0 {
		return "no-ocsp", fmt.Errorf("certificate has no OCSP server")
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return "error", fmt.Errorf("failed to create OCSP request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, cert.OCSPServer[0], bytes.NewReader(ocspReq))
	if err != nil {
		return "error", fmt.Errorf("failed to create OCSP HTTP request: %w", err)
	}
	request.Header.Set("Content-Type", "application/ocsp-request")
	request.Header.Set("Accept", "application/ocsp-response")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(request)
	if err != nil {
		return "error", fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "error", fmt.Errorf("OCSP responder returned HTTP %d", resp.StatusCode)
	}

	ocspResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error", fmt.Errorf("failed to read OCSP response: %w", err)
	}

	parsedResp, err := ocsp.ParseResponseForCert(ocspResp, cert, issuer)
	if err != nil {
		return "error", fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	switch parsedResp.Status {
	case ocsp.Good:
		return "good", nil
	case ocsp.Revoked:
		return "revoked", nil
	case ocsp.Unknown:
		return "unknown", nil
	default:
		return "unknown", fmt.Errorf("unexpected OCSP status: %d", parsedResp.Status)
	}
}

// LoadPinnedCertificates loads pinned certificate fingerprints
func (v *Validator) LoadPinnedCertificates(pinFile string) error {
	// TODO: Implement certificate pinning database
	return nil
}

// extractCertInfo extracts detailed information from a certificate
func extractCertInfo(cert *x509.Certificate) *CertificateInfo {
	now := time.Now()
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := &CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsExpired:          cert.NotAfter.Before(now),
		DaysUntilExpiry:    daysUntilExpiry,
		IsCA:               cert.IsCA,
		DNSNames:           cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		Version:            cert.Version,
		OCSPServer:         cert.OCSPServer,
		CRLDistribution:    cert.CRLDistributionPoints,
	}

	// Extract IP addresses
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// Extract key usages
	keyUsages := []string{}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, "KeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsages = append(keyUsages, "DataEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsages = append(keyUsages, "KeyAgreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsages = append(keyUsages, "CertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsages = append(keyUsages, "CRLSign")
	}
	info.KeyUsage = keyUsages

	// Extended key usages
	extKeyUsages := []string{}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsages = append(extKeyUsages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsages = append(extKeyUsages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsages = append(extKeyUsages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsages = append(extKeyUsages, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			extKeyUsages = append(extKeyUsages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUsages = append(extKeyUsages, "OCSPSigning")
		}
	}
	info.ExtKeyUsage = extKeyUsages

	return info
}

// getKeySize returns the key size for RSA/EC keys
func getKeySize(cert *x509.Certificate) int {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if pubKey, ok := cert.PublicKey.(interface{ Size() int }); ok {
			return pubKey.Size() * 8
		}
	case x509.ECDSA:
		// EC key sizes are typically 256, 384, or 521
		// Return approximate equivalent RSA strength
		return 256 // Simplified
	}
	return 0
}

// MonitorTLSConnections monitors network traffic for TLS handshakes
func (v *Validator) MonitorTLSConnections(iface string) error {
	// TODO: Implement packet capture and TLS handshake extraction
	// This will use gopacket to capture traffic and extract certificates
	return fmt.Errorf("not implemented yet")
}
