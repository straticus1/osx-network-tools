package discovery

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TLSConnection represents a captured TLS connection
type TLSConnection struct {
	Timestamp     time.Time
	SourceIP      string
	DestIP        string
	DestPort      uint16
	ServerName    string
	TLSVersion    string
	CipherSuites  []string
	ALPN          []string
	IsEncrypted   bool
}

// SNIExtractor extracts Server Name Indication from TLS handshakes
type SNIExtractor struct {
	Interface    string
	connections  map[string]*TLSConnection
	mu           sync.RWMutex
	callback     func(*TLSConnection)
}

// NewSNIExtractor creates a new SNI extractor
func NewSNIExtractor(iface string) *SNIExtractor {
	return &SNIExtractor{
		Interface:   iface,
		connections: make(map[string]*TLSConnection),
	}
}

// SetCallback sets a callback function for new TLS connections
func (se *SNIExtractor) SetCallback(cb func(*TLSConnection)) {
	se.callback = cb
}

// Start begins monitoring TLS traffic
func (se *SNIExtractor) Start() error {
	handle, err := pcap.OpenLive(se.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	// Set BPF filter for TLS traffic (port 443 and other common TLS ports)
	if err := handle.SetBPFFilter("tcp port 443 or tcp port 8443"); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Monitoring TLS/HTTPS traffic on %s...\n", se.Interface)

	for packet := range packetSource.Packets() {
		se.processPacket(packet)
	}

	return nil
}

// processPacket processes a captured packet
func (se *SNIExtractor) processPacket(packet gopacket.Packet) {
	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// Check if this is a TLS ClientHello
	payload := tcp.Payload
	if len(payload) < 5 {
		return
	}

	// TLS record header: ContentType (1 byte) + Version (2 bytes) + Length (2 bytes)
	// ContentType 0x16 = Handshake
	if payload[0] != 0x16 {
		return
	}

	// Extract connection info
	var sourceIP, destIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		sourceIP = ip.SrcIP.String()
		destIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		sourceIP = ip.SrcIP.String()
		destIP = ip.DstIP.String()
	}

	// Parse TLS handshake
	conn := se.parseTLSClientHello(payload)
	if conn == nil {
		return
	}

	conn.Timestamp = time.Now()
	conn.SourceIP = sourceIP
	conn.DestIP = destIP
	conn.DestPort = uint16(tcp.DstPort)

	// Store connection
	se.mu.Lock()
	key := fmt.Sprintf("%s:%s:%d", sourceIP, destIP, tcp.DstPort)
	se.connections[key] = conn
	se.mu.Unlock()

	// Callback
	if se.callback != nil {
		se.callback(conn)
	}
}

// parseTLSClientHello parses TLS ClientHello message
func (se *SNIExtractor) parseTLSClientHello(data []byte) *TLSConnection {
	if len(data) < 43 {
		return nil
	}

	// Skip TLS record header (5 bytes)
	pos := 5

	// Handshake type (1 byte) - should be 0x01 for ClientHello
	if data[pos] != 0x01 {
		return nil
	}
	pos++

	// Handshake length (3 bytes)
	pos += 3

	// TLS version (2 bytes)
	tlsVersion := se.parseTLSVersion(data[pos : pos+2])
	pos += 2

	// Random (32 bytes)
	pos += 32

	// Session ID length (1 byte)
	if pos >= len(data) {
		return nil
	}
	sessionIDLen := int(data[pos])
	pos++

	// Session ID
	pos += sessionIDLen

	// Cipher suites length (2 bytes)
	if pos+2 >= len(data) {
		return nil
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	// Skip cipher suites
	pos += cipherSuitesLen

	// Compression methods length (1 byte)
	if pos >= len(data) {
		return nil
	}
	compressionLen := int(data[pos])
	pos++

	// Skip compression methods
	pos += compressionLen

	// Extensions
	if pos+2 >= len(data) {
		return nil
	}

	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	conn := &TLSConnection{
		TLSVersion:  tlsVersion,
		IsEncrypted: true,
	}

	// Parse extensions
	endPos := pos + extensionsLen
	for pos < endPos && pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		extLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if pos+extLen > len(data) {
			break
		}

		switch extType {
		case 0x0000: // Server Name Indication
			conn.ServerName = se.parseServerName(data[pos : pos+extLen])
		case 0x0010: // ALPN
			conn.ALPN = se.parseALPN(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return conn
}

// parseTLSVersion converts TLS version bytes to string
func (se *SNIExtractor) parseTLSVersion(data []byte) string {
	if len(data) < 2 {
		return "Unknown"
	}

	major := data[0]
	minor := data[1]

	switch {
	case major == 3 && minor == 0:
		return "SSL 3.0"
	case major == 3 && minor == 1:
		return "TLS 1.0"
	case major == 3 && minor == 2:
		return "TLS 1.1"
	case major == 3 && minor == 3:
		return "TLS 1.2"
	case major == 3 && minor == 4:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d.%d)", major, minor)
	}
}

// parseServerName extracts server name from SNI extension
func (se *SNIExtractor) parseServerName(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Server name list length (2 bytes)
	pos := 2

	// Server name type (1 byte) - should be 0x00 for hostname
	if data[pos] != 0x00 {
		return ""
	}
	pos++

	// Server name length (2 bytes)
	nameLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+nameLen > len(data) {
		return ""
	}

	return string(data[pos : pos+nameLen])
}

// parseALPN extracts ALPN protocols
func (se *SNIExtractor) parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	protocols := []string{}
	pos := 2 // Skip length

	for pos < len(data) {
		if pos >= len(data) {
			break
		}

		protoLen := int(data[pos])
		pos++

		if pos+protoLen > len(data) {
			break
		}

		protocols = append(protocols, string(data[pos:pos+protoLen]))
		pos += protoLen
	}

	return protocols
}

// GetConnections returns all captured TLS connections
func (se *SNIExtractor) GetConnections() []*TLSConnection {
	se.mu.RLock()
	defer se.mu.RUnlock()

	connections := make([]*TLSConnection, 0, len(se.connections))
	for _, conn := range se.connections {
		connections = append(connections, conn)
	}

	return connections
}

// GetUniqueHosts returns unique hostnames seen
func (se *SNIExtractor) GetUniqueHosts() []string {
	se.mu.RLock()
	defer se.mu.RUnlock()

	hosts := make(map[string]bool)
	for _, conn := range se.connections {
		if conn.ServerName != "" {
			hosts[conn.ServerName] = true
		}
	}

	result := make([]string, 0, len(hosts))
	for host := range hosts {
		result = append(result, host)
	}

	return result
}

// IdentifyService attempts to identify the service from hostname
func (se *SNIExtractor) IdentifyService(hostname string) string {
	hostname = strings.ToLower(hostname)

	// Cloud services
	cloudServices := map[string]string{
		"amazonaws.com":    "AWS",
		"azure.com":        "Azure",
		"googleapis.com":   "Google Cloud",
		"cloudflare.com":   "Cloudflare",
		"akamai.net":       "Akamai",
		"fastly.net":       "Fastly",
	}

	for pattern, service := range cloudServices {
		if strings.Contains(hostname, pattern) {
			return service
		}
	}

	// SaaS services
	saasServices := map[string]string{
		"dropbox.com":    "Dropbox",
		"box.com":        "Box",
		"drive.google":   "Google Drive",
		"slack.com":      "Slack",
		"github.com":     "GitHub",
		"gitlab.com":     "GitLab",
		"salesforce.com": "Salesforce",
		"zoom.us":        "Zoom",
		"teams.microsoft": "Microsoft Teams",
		"webex.com":      "Webex",
	}

	for pattern, service := range saasServices {
		if strings.Contains(hostname, pattern) {
			return service
		}
	}

	return "Unknown"
}

// GetServiceStatistics returns statistics about services
func (se *SNIExtractor) GetServiceStatistics() map[string]int {
	se.mu.RLock()
	defer se.mu.RUnlock()

	stats := make(map[string]int)

	for _, conn := range se.connections {
		if conn.ServerName == "" {
			continue
		}

		service := se.IdentifyService(conn.ServerName)
		stats[service]++
	}

	return stats
}
