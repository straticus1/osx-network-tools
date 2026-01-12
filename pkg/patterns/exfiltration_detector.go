package patterns

import (
	"fmt"
	"strings"
	"time"

	"github.com/yourusername/osx-network-tools/pkg/egress"
)

// ExfiltrationPattern represents a detected exfiltration pattern
type ExfiltrationPattern struct {
	Type        string
	Severity    string
	Description string
	Connection  *egress.Connection
	Confidence  float64
	Timestamp   time.Time
	Indicators  []string
}

// ExfiltrationDetector detects data exfiltration patterns
type ExfiltrationDetector struct {
	thresholds DetectionThresholds
	patterns   []*ExfiltrationPattern
	baseline   *Baseline
}

// DetectionThresholds defines thresholds for detection
type DetectionThresholds struct {
	LargeUploadBytes      uint64  // Bytes
	LargeUploadDuration   int     // Seconds
	UnusualPortConnections int    // Count
	HighEntropyThreshold  float64 // 0.0 - 1.0
	DNSTunnelQueriesMin   int     // Queries per minute
	BeaconingJitterMax    float64 // Seconds
}

// Baseline represents normal network behavior
type Baseline struct {
	AvgBytesPerConnection uint64
	AvgConnectionDuration time.Duration
	CommonPorts           map[uint16]int
	CommonDestinations    map[string]int
}

// NewExfiltrationDetector creates a new exfiltration detector
func NewExfiltrationDetector() *ExfiltrationDetector {
	return &ExfiltrationDetector{
		thresholds: DetectionThresholds{
			LargeUploadBytes:      100 * 1024 * 1024, // 100 MB
			LargeUploadDuration:   300,                // 5 minutes
			UnusualPortConnections: 5,
			HighEntropyThreshold:  0.75,
			DNSTunnelQueriesMin:   10,
			BeaconingJitterMax:    5.0,
		},
		patterns: make([]*ExfiltrationPattern, 0),
	}
}

// SetThresholds sets custom detection thresholds
func (ed *ExfiltrationDetector) SetThresholds(t DetectionThresholds) {
	ed.thresholds = t
}

// AnalyzeConnection analyzes a connection for exfiltration patterns
func (ed *ExfiltrationDetector) AnalyzeConnection(conn *egress.Connection) []*ExfiltrationPattern {
	patterns := make([]*ExfiltrationPattern, 0)

	// Check for large uploads
	if pattern := ed.detectLargeUpload(conn); pattern != nil {
		patterns = append(patterns, pattern)
	}

	// Check for unusual ports
	if pattern := ed.detectUnusualPort(conn); pattern != nil {
		patterns = append(patterns, pattern)
	}

	// Check for uncommon protocols
	if pattern := ed.detectUncommonProtocol(conn); pattern != nil {
		patterns = append(patterns, pattern)
	}

	// Check for suspicious destinations
	if pattern := ed.detectSuspiciousDestination(conn); pattern != nil {
		patterns = append(patterns, pattern)
	}

	// Check for long-duration connections
	if pattern := ed.detectLongConnection(conn); pattern != nil {
		patterns = append(patterns, pattern)
	}

	// Store detected patterns
	ed.patterns = append(ed.patterns, patterns...)

	return patterns
}

// detectLargeUpload detects unusually large uploads
func (ed *ExfiltrationDetector) detectLargeUpload(conn *egress.Connection) *ExfiltrationPattern {
	if !conn.IsOutbound {
		return nil
	}

	if conn.BytesSent > ed.thresholds.LargeUploadBytes {
		return &ExfiltrationPattern{
			Type:        "LargeUpload",
			Severity:    "HIGH",
			Description: fmt.Sprintf("Large data upload detected: %s", egress.FormatBytes(conn.BytesSent)),
			Connection:  conn,
			Confidence:  0.8,
			Timestamp:   time.Now(),
			Indicators: []string{
				fmt.Sprintf("Uploaded %s", egress.FormatBytes(conn.BytesSent)),
				fmt.Sprintf("Destination: %s:%d", conn.DestIP, conn.DestPort),
			},
		}
	}

	return nil
}

// detectUnusualPort detects connections to unusual ports
func (ed *ExfiltrationDetector) detectUnusualPort(conn *egress.Connection) *ExfiltrationPattern {
	// Common legitimate ports
	commonPorts := map[uint16]bool{
		80:   true, // HTTP
		443:  true, // HTTPS
		22:   true, // SSH
		21:   true, // FTP
		25:   true, // SMTP
		53:   true, // DNS
		110:  true, // POP3
		143:  true, // IMAP
		3306: true, // MySQL
		5432: true, // PostgreSQL
		6379: true, // Redis
		8080: true, // HTTP Alt
		8443: true, // HTTPS Alt
	}

	if !commonPorts[conn.DestPort] && conn.IsOutbound {
		severity := "MEDIUM"
		confidence := 0.5

		// Higher severity for very high ports
		if conn.DestPort > 49152 {
			severity = "HIGH"
			confidence = 0.7
		}

		return &ExfiltrationPattern{
			Type:        "UnusualPort",
			Severity:    severity,
			Description: fmt.Sprintf("Connection to unusual port %d", conn.DestPort),
			Connection:  conn,
			Confidence:  confidence,
			Timestamp:   time.Now(),
			Indicators: []string{
				fmt.Sprintf("Port: %d", conn.DestPort),
				fmt.Sprintf("Destination: %s", conn.DestIP),
				fmt.Sprintf("Data sent: %s", egress.FormatBytes(conn.BytesSent)),
			},
		}
	}

	return nil
}

// detectUncommonProtocol detects uncommon protocols
func (ed *ExfiltrationDetector) detectUncommonProtocol(conn *egress.Connection) *ExfiltrationPattern {
	// Most traffic should be TCP
	if conn.Protocol == "UDP" && conn.BytesSent > 1024*1024 && conn.DestPort != 53 {
		return &ExfiltrationPattern{
			Type:        "UncommonProtocol",
			Severity:    "MEDIUM",
			Description: "Large data transfer over UDP",
			Connection:  conn,
			Confidence:  0.6,
			Timestamp:   time.Now(),
			Indicators: []string{
				"Protocol: UDP",
				fmt.Sprintf("Data sent: %s", egress.FormatBytes(conn.BytesSent)),
				fmt.Sprintf("Port: %d", conn.DestPort),
			},
		}
	}

	return nil
}

// detectSuspiciousDestination detects suspicious destination IPs
func (ed *ExfiltrationDetector) detectSuspiciousDestination(conn *egress.Connection) *ExfiltrationPattern {
	// Check for connections to Tor exit nodes, known C2 servers, etc.
	// This is a simplified example - in production, integrate with threat intelligence

	suspiciousPatterns := []string{
		"185.220.", // Known Tor range
		"104.244.", // Some bulletproof hosting
	}

	for _, pattern := range suspiciousPatterns {
		if strings.HasPrefix(conn.DestIP, pattern) {
			return &ExfiltrationPattern{
				Type:        "SuspiciousDestination",
				Severity:    "CRITICAL",
				Description: "Connection to suspicious IP range",
				Connection:  conn,
				Confidence:  0.9,
				Timestamp:   time.Now(),
				Indicators: []string{
					fmt.Sprintf("IP: %s", conn.DestIP),
					"Matches known suspicious pattern",
					fmt.Sprintf("Data sent: %s", egress.FormatBytes(conn.BytesSent)),
				},
			}
		}
	}

	return nil
}

// detectLongConnection detects unusually long connections
func (ed *ExfiltrationDetector) detectLongConnection(conn *egress.Connection) *ExfiltrationPattern {
	duration := conn.LastSeen.Sub(conn.StartTime)

	// Connections lasting > 1 hour with data transfer
	if duration > time.Hour && conn.BytesSent > 1024*1024 {
		return &ExfiltrationPattern{
			Type:        "LongConnection",
			Severity:    "MEDIUM",
			Description: "Long-duration connection with data transfer",
			Connection:  conn,
			Confidence:  0.6,
			Timestamp:   time.Now(),
			Indicators: []string{
				fmt.Sprintf("Duration: %v", duration),
				fmt.Sprintf("Data sent: %s", egress.FormatBytes(conn.BytesSent)),
				fmt.Sprintf("Destination: %s:%d", conn.DestIP, conn.DestPort),
			},
		}
	}

	return nil
}

// DetectBeaconing detects periodic communication (C2 beaconing)
func (ed *ExfiltrationDetector) DetectBeaconing(connections []*egress.Connection) []*ExfiltrationPattern {
	patterns := make([]*ExfiltrationPattern, 0)

	// Group connections by destination
	byDest := make(map[string][]*egress.Connection)
	for _, conn := range connections {
		key := fmt.Sprintf("%s:%d", conn.DestIP, conn.DestPort)
		byDest[key] = append(byDest[key], conn)
	}

	// Analyze each destination for beaconing
	for dest, conns := range byDest {
		if len(conns) < 5 {
			continue // Need multiple connections
		}

		// Calculate intervals between connections
		intervals := make([]float64, 0, len(conns)-1)
		for i := 1; i < len(conns); i++ {
			interval := conns[i].StartTime.Sub(conns[i-1].StartTime).Seconds()
			intervals = append(intervals, interval)
		}

		// Calculate average and jitter
		avg := average(intervals)
		jitter := standardDeviation(intervals, avg)

		// Low jitter indicates beaconing
		if jitter < ed.thresholds.BeaconingJitterMax && avg > 10 && avg < 300 {
			pattern := &ExfiltrationPattern{
				Type:        "Beaconing",
				Severity:    "CRITICAL",
				Description: fmt.Sprintf("Periodic beaconing detected to %s", dest),
				Connection:  conns[0], // Reference first connection
				Confidence:  0.85,
				Timestamp:   time.Now(),
				Indicators: []string{
					fmt.Sprintf("Connections: %d", len(conns)),
					fmt.Sprintf("Avg interval: %.1f seconds", avg),
					fmt.Sprintf("Jitter: %.1f seconds", jitter),
					"Indicates possible C2 communication",
				},
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// DetectDNSTunneling detects DNS tunneling
func (ed *ExfiltrationDetector) DetectDNSTunneling(dnsQueries []DNSQuery) []*ExfiltrationPattern {
	patterns := make([]*ExfiltrationPattern, 0)

	// Group queries by domain
	byDomain := make(map[string][]DNSQuery)
	for _, query := range dnsQueries {
		domain := extractBaseDomain(query.Domain)
		byDomain[domain] = append(byDomain[domain], query)
	}

	// Analyze each domain
	for domain, queries := range byDomain {
		// High query rate
		if len(queries) > ed.thresholds.DNSTunnelQueriesMin {
			// Check for suspicious patterns
			hasLongSubdomains := false
			hasHighEntropy := false

			for _, query := range queries {
				if len(query.Domain) > 50 {
					hasLongSubdomains = true
				}
				if calculateEntropy(query.Domain) > 4.0 {
					hasHighEntropy = true
				}
			}

			if hasLongSubdomains || hasHighEntropy {
				pattern := &ExfiltrationPattern{
					Type:        "DNSTunneling",
					Severity:    "HIGH",
					Description: fmt.Sprintf("Possible DNS tunneling to %s", domain),
					Confidence:  0.75,
					Timestamp:   time.Now(),
					Indicators: []string{
						fmt.Sprintf("Queries: %d", len(queries)),
						fmt.Sprintf("Domain: %s", domain),
					},
				}

				if hasLongSubdomains {
					pattern.Indicators = append(pattern.Indicators, "Long subdomains detected")
				}
				if hasHighEntropy {
					pattern.Indicators = append(pattern.Indicators, "High entropy detected")
				}

				patterns = append(patterns, pattern)
			}
		}
	}

	return patterns
}

// DNSQuery represents a DNS query (simplified)
type DNSQuery struct {
	Domain    string
	Timestamp time.Time
}

// GetPatterns returns all detected patterns
func (ed *ExfiltrationDetector) GetPatterns() []*ExfiltrationPattern {
	return ed.patterns
}

// GetPatternsBySeverity returns patterns filtered by severity
func (ed *ExfiltrationDetector) GetPatternsBySeverity(severity string) []*ExfiltrationPattern {
	patterns := make([]*ExfiltrationPattern, 0)
	for _, p := range ed.patterns {
		if p.Severity == severity {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// Helper functions

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func standardDeviation(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	return variance // Simplified - not taking square root for comparison
}

func extractBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

func calculateEntropy(s string) float64 {
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
			entropy -= p * (0.693147 * float64(count))
		}
	}

	return entropy
}
