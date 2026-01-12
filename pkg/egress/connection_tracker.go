package egress

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Connection represents a network connection
type Connection struct {
	SourceIP     string
	SourcePort   uint16
	DestIP       string
	DestPort     uint16
	Protocol     string
	StartTime    time.Time
	LastSeen     time.Time
	BytesSent    uint64
	BytesRecv    uint64
	PacketsSent  uint64
	PacketsRecv  uint64
	Hostname     string
	Process      string
	IsOutbound   bool
	IsSuspicious bool
	Flags        []string
}

// ConnectionTracker tracks network connections
type ConnectionTracker struct {
	Interface   string
	connections map[string]*Connection
	mu          sync.RWMutex
	callback    func(*Connection)
	localNets   []string
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker(iface string) *ConnectionTracker {
	return &ConnectionTracker{
		Interface:   iface,
		connections: make(map[string]*Connection),
		localNets: []string{
			"192.168.",
			"10.",
			"172.16.",
			"172.17.",
			"172.18.",
			"172.19.",
			"172.20.",
			"172.21.",
			"172.22.",
			"172.23.",
			"172.24.",
			"172.25.",
			"172.26.",
			"172.27.",
			"172.28.",
			"172.29.",
			"172.30.",
			"172.31.",
			"127.",
		},
	}
}

// SetCallback sets a callback for new connections
func (ct *ConnectionTracker) SetCallback(cb func(*Connection)) {
	ct.callback = cb
}

// Start begins tracking connections
func (ct *ConnectionTracker) Start() error {
	handle, err := pcap.OpenLive(ct.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	// Filter for TCP and UDP
	if err := handle.SetBPFFilter("tcp or udp"); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Tracking connections on %s...\n", ct.Interface)

	for packet := range packetSource.Packets() {
		ct.processPacket(packet)
	}

	return nil
}

// processPacket processes a captured packet
func (ct *ConnectionTracker) processPacket(packet gopacket.Packet) {
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var protocol string
	var dataLen uint64

	// Get IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		dataLen = uint64(ip.Length)
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		dataLen = uint64(ip.Length)
	} else {
		return
	}

	// Get transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "UDP"
	} else {
		return
	}

	// Determine direction (outbound vs inbound)
	isOutbound := ct.isLocalIP(srcIP) && !ct.isLocalIP(dstIP)

	// Create connection key
	key := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

	ct.mu.Lock()
	conn, exists := ct.connections[key]
	if !exists {
		conn = &Connection{
			SourceIP:   srcIP,
			SourcePort: srcPort,
			DestIP:     dstIP,
			DestPort:   dstPort,
			Protocol:   protocol,
			StartTime:  time.Now(),
			LastSeen:   time.Now(),
			IsOutbound: isOutbound,
			Flags:      []string{},
		}
		ct.connections[key] = conn

		// Trigger callback for new connection
		if ct.callback != nil {
			ct.callback(conn)
		}
	} else {
		conn.LastSeen = time.Now()
	}

	// Update statistics
	if isOutbound {
		conn.BytesSent += dataLen
		conn.PacketsSent++
	} else {
		conn.BytesRecv += dataLen
		conn.PacketsRecv++
	}

	ct.mu.Unlock()
}

// isLocalIP checks if an IP is local/private
func (ct *ConnectionTracker) isLocalIP(ip string) bool {
	for _, prefix := range ct.localNets {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// GetConnections returns all tracked connections
func (ct *ConnectionTracker) GetConnections() []*Connection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	connections := make([]*Connection, 0, len(ct.connections))
	for _, conn := range ct.connections {
		connections = append(connections, conn)
	}

	return connections
}

// GetOutboundConnections returns only outbound connections
func (ct *ConnectionTracker) GetOutboundConnections() []*Connection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	connections := make([]*Connection, 0)
	for _, conn := range ct.connections {
		if conn.IsOutbound {
			connections = append(connections, conn)
		}
	}

	return connections
}

// GetTopTalkers returns connections sorted by data transferred
func (ct *ConnectionTracker) GetTopTalkers(limit int) []*Connection {
	connections := ct.GetOutboundConnections()

	// Sort by bytes sent (descending)
	for i := 0; i < len(connections)-1; i++ {
		for j := i + 1; j < len(connections); j++ {
			if connections[i].BytesSent < connections[j].BytesSent {
				connections[i], connections[j] = connections[j], connections[i]
			}
		}
	}

	if len(connections) > limit {
		connections = connections[:limit]
	}

	return connections
}

// GetConnectionsByPort returns connections for a specific port
func (ct *ConnectionTracker) GetConnectionsByPort(port uint16) []*Connection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	connections := make([]*Connection, 0)
	for _, conn := range ct.connections {
		if conn.DestPort == port {
			connections = append(connections, conn)
		}
	}

	return connections
}

// GetConnectionStatistics returns statistics about connections
func (ct *ConnectionTracker) GetConnectionStatistics() *ConnectionStats {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	stats := &ConnectionStats{
		TotalConnections:    len(ct.connections),
		OutboundConnections: 0,
		InboundConnections:  0,
		TotalBytesSent:      0,
		TotalBytesRecv:      0,
		ByProtocol:          make(map[string]int),
		ByPort:              make(map[uint16]int),
		SuspiciousCount:     0,
	}

	for _, conn := range ct.connections {
		if conn.IsOutbound {
			stats.OutboundConnections++
			stats.TotalBytesSent += conn.BytesSent
		} else {
			stats.InboundConnections++
		}
		stats.TotalBytesRecv += conn.BytesRecv

		stats.ByProtocol[conn.Protocol]++
		stats.ByPort[conn.DestPort]++

		if conn.IsSuspicious {
			stats.SuspiciousCount++
		}
	}

	return stats
}

// ConnectionStats holds connection statistics
type ConnectionStats struct {
	TotalConnections    int
	OutboundConnections int
	InboundConnections  int
	TotalBytesSent      uint64
	TotalBytesRecv      uint64
	ByProtocol          map[string]int
	ByPort              map[uint16]int
	SuspiciousCount     int
}

// CleanupStaleConnections removes old connections
func (ct *ConnectionTracker) CleanupStaleConnections(maxAge time.Duration) int {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	count := 0
	now := time.Now()

	for key, conn := range ct.connections {
		if now.Sub(conn.LastSeen) > maxAge {
			delete(ct.connections, key)
			count++
		}
	}

	return count
}

// FormatBytes formats bytes to human-readable format
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
