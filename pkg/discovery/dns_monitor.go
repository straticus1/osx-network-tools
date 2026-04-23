package discovery

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// DNSQuery represents a captured DNS query
type DNSQuery struct {
	Timestamp   time.Time
	SourceIP    string
	QueryName   string
	QueryType   string
	Answers     []string
	ResponseIPs []string
	TTL         uint32
}

// DNSMonitor captures and analyzes DNS traffic
type DNSMonitor struct {
	Interface     string
	queries       map[string]*DNSQuery
	mu            sync.RWMutex
	callback      func(*DNSQuery)
	knownDomains  map[string]bool
	suspiciousTLDs map[string]bool
}

// NewDNSMonitor creates a new DNS monitor
func NewDNSMonitor(iface string) *DNSMonitor {
	return &DNSMonitor{
		Interface:     iface,
		queries:       make(map[string]*DNSQuery),
		knownDomains:  make(map[string]bool),
		suspiciousTLDs: map[string]bool{
			".tk":  true, // Free TLDs often used for malicious purposes
			".ml":  true,
			".ga":  true,
			".cf":  true,
			".gq":  true,
			".xyz": true,
		},
	}
}

// SetCallback sets a callback function for new DNS queries
func (dm *DNSMonitor) SetCallback(cb func(*DNSQuery)) {
	dm.callback = cb
}

// Start begins monitoring DNS traffic
func (dm *DNSMonitor) Start() error {
	handle, err := pcap.OpenLive(dm.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	// Set BPF filter for DNS traffic (port 53)
	if err := handle.SetBPFFilter("udp port 53 or tcp port 53"); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Monitoring DNS traffic on %s...\n", dm.Interface)

	for packet := range packetSource.Packets() {
		dm.processPacket(packet)
	}

	return nil
}

// processPacket processes a captured packet
func (dm *DNSMonitor) processPacket(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return
	}

	// Get source IP
	var sourceIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		sourceIP = ip.SrcIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		sourceIP = ip.SrcIP.String()
	}

	// Process DNS queries
	if !dns.QR { // Query
		for _, question := range dns.Questions {
			query := &DNSQuery{
				Timestamp: time.Now(),
				SourceIP:  sourceIP,
				QueryName: string(question.Name),
				QueryType: question.Type.String(),
			}

			dm.mu.Lock()
			key := fmt.Sprintf("%s:%s", sourceIP, query.QueryName)
			dm.queries[key] = query
			dm.mu.Unlock()

			if dm.callback != nil {
				dm.callback(query)
			}
		}
	} else { // Response
		for _, question := range dns.Questions {
			key := fmt.Sprintf("%s:%s", sourceIP, string(question.Name))

			dm.mu.Lock()
			if query, exists := dm.queries[key]; exists {
				// Add answers
				for _, answer := range dns.Answers {
					if answer.IP != nil {
						query.ResponseIPs = append(query.ResponseIPs, answer.IP.String())
					}
					if len(answer.CNAME) > 0 {
						query.Answers = append(query.Answers, string(answer.CNAME))
					}
					query.TTL = answer.TTL
				}
			}
			dm.mu.Unlock()
		}
	}
}

// GetQueries returns all captured DNS queries
func (dm *DNSMonitor) GetQueries() []*DNSQuery {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	queries := make([]*DNSQuery, 0, len(dm.queries))
	for _, q := range dm.queries {
		queries = append(queries, q)
	}
	return queries
}

// IsSuspiciousDomain checks if a domain is suspicious
func (dm *DNSMonitor) IsSuspiciousDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// Check for suspicious TLDs
	for tld := range dm.suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}

	// Check for suspicious patterns
	if dm.hasDataExfiltrationPattern(domain) {
		return true
	}

	// Check for DNS tunneling indicators
	if dm.isDNSTunneling(domain) {
		return true
	}

	return false
}

// hasDataExfiltrationPattern checks for data exfiltration patterns
func (dm *DNSMonitor) hasDataExfiltrationPattern(domain string) bool {
	parts := strings.Split(domain, ".")

	for _, part := range parts {
		// Very long subdomain (possible data encoding)
		if len(part) > 50 {
			return true
		}

		// High entropy (random-looking strings)
		if dm.calculateEntropy(part) > 4.5 {
			return true
		}

		// Base64-like patterns
		if dm.looksLikeBase64(part) && len(part) > 20 {
			return true
		}
	}

	return false
}

// isDNSTunneling checks for DNS tunneling indicators
func (dm *DNSMonitor) isDNSTunneling(domain string) bool {
	parts := strings.Split(domain, ".")

	// Many subdomains (> 5)
	if len(parts) > 5 {
		return true
	}

	// Calculate total length
	totalLen := len(domain)
	if totalLen > 100 {
		return true
	}

	return false
}

// calculateEntropy calculates Shannon entropy of a string
func (dm *DNSMonitor) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * (0.693147 * float64(count)) // Using natural log approximation
		}
	}

	return entropy
}

// looksLikeBase64 checks if string looks like base64
func (dm *DNSMonitor) looksLikeBase64(s string) bool {
	base64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	if len(s) < 4 {
		return false
	}

	validChars := 0
	for _, c := range s {
		if strings.ContainsRune(base64Chars, c) {
			validChars++
		}
	}

	return float64(validChars)/float64(len(s)) > 0.9
}

// ExtractCloudServices identifies cloud services from DNS queries
func (dm *DNSMonitor) ExtractCloudServices() []CloudService {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	services := make(map[string]*CloudService)

	for _, query := range dm.queries {
		if service := dm.identifyCloudService(query.QueryName); service != nil {
			key := service.Provider + ":" + service.ServiceName
			if existing, exists := services[key]; exists {
				existing.AccessCount++
				existing.LastSeen = query.Timestamp
			} else {
				service.FirstSeen = query.Timestamp
				service.LastSeen = query.Timestamp
				service.AccessCount = 1
				services[key] = service
			}
		}
	}

	result := make([]CloudService, 0, len(services))
	for _, service := range services {
		result = append(result, *service)
	}

	return result
}

// CloudService represents an identified cloud service
type CloudService struct {
	Provider    string
	ServiceName string
	Domain      string
	FirstSeen   time.Time
	LastSeen    time.Time
	AccessCount int
	IsApproved  bool
}

// IdentifyCloudService identifies cloud service from domain
func (dm *DNSMonitor) IdentifyCloudService(domain string) *CloudService {
	return dm.identifyCloudService(domain)
}

// identifyCloudService identifies cloud service from domain
func (dm *DNSMonitor) identifyCloudService(domain string) *CloudService {
	domain = strings.ToLower(domain)

	// AWS Services
	if strings.Contains(domain, "amazonaws.com") {
		return &CloudService{
			Provider:    "AWS",
			ServiceName: dm.identifyAWSService(domain),
			Domain:      domain,
		}
	}

	// Azure Services
	if strings.Contains(domain, "azure.com") || strings.Contains(domain, "microsoft.com") {
		return &CloudService{
			Provider:    "Azure",
			ServiceName: dm.identifyAzureService(domain),
			Domain:      domain,
		}
	}

	// Google Cloud
	if strings.Contains(domain, "googleapis.com") || strings.Contains(domain, "gcp.") {
		return &CloudService{
			Provider:    "GCP",
			ServiceName: dm.identifyGCPService(domain),
			Domain:      domain,
		}
	}

	// SaaS Applications
	saasServices := map[string]string{
		"dropbox.com":       "Dropbox",
		"box.com":           "Box",
		"drive.google.com":  "Google Drive",
		"onedrive.com":      "OneDrive",
		"slack.com":         "Slack",
		"zoom.us":           "Zoom",
		"github.com":        "GitHub",
		"gitlab.com":        "GitLab",
		"salesforce.com":    "Salesforce",
		"atlassian.net":     "Atlassian",
		"notion.so":         "Notion",
		"airtable.com":      "Airtable",
		"monday.com":        "Monday.com",
		"asana.com":         "Asana",
		"trello.com":        "Trello",
	}

	for pattern, name := range saasServices {
		if strings.Contains(domain, pattern) {
			return &CloudService{
				Provider:    "SaaS",
				ServiceName: name,
				Domain:      domain,
			}
		}
	}

	return nil
}

// identifyAWSService identifies specific AWS service
func (dm *DNSMonitor) identifyAWSService(domain string) string {
	if strings.Contains(domain, "s3") {
		return "S3"
	} else if strings.Contains(domain, "ec2") {
		return "EC2"
	} else if strings.Contains(domain, "rds") {
		return "RDS"
	} else if strings.Contains(domain, "lambda") {
		return "Lambda"
	} else if strings.Contains(domain, "cloudfront") {
		return "CloudFront"
	} else if strings.Contains(domain, "dynamodb") {
		return "DynamoDB"
	}
	return "AWS (Unknown)"
}

// identifyAzureService identifies specific Azure service
func (dm *DNSMonitor) identifyAzureService(domain string) string {
	if strings.Contains(domain, "blob") {
		return "Blob Storage"
	} else if strings.Contains(domain, "database") {
		return "SQL Database"
	} else if strings.Contains(domain, "vault") {
		return "Key Vault"
	}
	return "Azure (Unknown)"
}

// identifyGCPService identifies specific GCP service
func (dm *DNSMonitor) identifyGCPService(domain string) string {
	if strings.Contains(domain, "storage") {
		return "Cloud Storage"
	} else if strings.Contains(domain, "compute") {
		return "Compute Engine"
	} else if strings.Contains(domain, "firestore") {
		return "Firestore"
	}
	return "GCP (Unknown)"
}

// ResolveDomain resolves a domain to IP addresses
func ResolveDomain(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}
