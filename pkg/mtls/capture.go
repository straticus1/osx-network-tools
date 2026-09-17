package mtls

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// TLS 1.2 certificates are visible in plaintext handshakes. TLS 1.3 encrypts
// certificate messages; passive capture cannot validate those certificates.
func (v *Validator) MonitorTLSConnections(iface string) error {
	if iface == "" {
		return fmt.Errorf("capture interface is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	command := exec.CommandContext(ctx, "tcpdump", "-i", iface, "-U", "-n", "-s", "0", "-w", "-", "tcp port 443")
	command.Stderr = os.Stderr
	pipe, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("tcpdump capture unavailable: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Observing plaintext TLS 1.2 certificate handshakes on TCP/443; encrypted TLS 1.3 certificates are not observable.")
	err = v.inspectPCAP(pipe, os.Stdout)
	if err != nil {
		cancel()
	}
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return err
	}
	if err != nil {
		return err
	}
	return waitErr
}

type certificateStreams struct {
	v      *Validator
	out    io.Writer
	mu     sync.Mutex
	wg     sync.WaitGroup
	active atomic.Int32
	err    error
}
type discardedStream struct{}

func (*discardedStream) Reassembled([]tcpassembly.Reassembly) {}
func (*discardedStream) ReassemblyComplete()                  {}

func (f *certificateStreams) New(network, transport gopacket.Flow) tcpassembly.Stream {
	if f.active.Add(1) > 1024 {
		f.active.Add(-1)
		return &discardedStream{}
	}
	reader := tcpreader.NewReaderStream()
	reader.LossErrors = true
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer f.active.Add(-1)
		defer reader.Close()
		_ = readCertificates(&reader, func(chain []*x509.Certificate) error {
			result := f.v.ValidateCertificate(chain[0], chain[1:])
			f.mu.Lock()
			defer f.mu.Unlock()
			err := json.NewEncoder(f.out).Encode(map[string]any{"source": network.Src().String(), "destination": network.Dst().String(), "ports": transport.String(), "observation": "plaintext_tls_certificate", "hostname_verified": false, "validation": result})
			if err != nil {
				f.err = err
			}
			return err
		})
	}()
	return &reader
}

func (v *Validator) inspectPCAP(input io.Reader, output io.Writer) error {
	reader, err := pcapgo.NewReader(input)
	if err != nil {
		return err
	}
	factory := &certificateStreams{v: v, out: output}
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	assembler.MaxBufferedPagesTotal = 8192
	assembler.MaxBufferedPagesPerConnection = 256
	count := 0
	for {
		data, info, err := reader.ReadPacketData()
		if err != nil {
			assembler.FlushAll()
			factory.wg.Wait()
			if err != io.EOF {
				return err
			}
			return factory.err
		}
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.NoCopy)
		if packet.NetworkLayer() == nil {
			continue
		}
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, info.Timestamp)
		count++
		if count%100 == 0 {
			assembler.FlushOlderThan(info.Timestamp.Add(-time.Minute))
		}
	}
}

func u24(data []byte) int { return int(data[0])<<16 | int(data[1])<<8 | int(data[2]) }

func readCertificates(reader io.Reader, emit func([]*x509.Certificate) error) error {
	var handshake []byte
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(reader, header); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[1] != 3 || header[2] > 3 || length > 18432 {
			return fmt.Errorf("unsupported or malformed TLS record")
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return err
		}
		if header[0] != 22 {
			continue
		}
		handshake = append(handshake, body...)
		if len(handshake) > 1<<20 {
			return fmt.Errorf("TLS handshake exceeds 1 MiB")
		}
		for len(handshake) >= 4 {
			size := u24(handshake[1:4])
			if size > 1<<20 {
				return fmt.Errorf("TLS handshake exceeds 1 MiB")
			}
			if len(handshake) < size+4 {
				break
			}
			if handshake[0] == 11 {
				message := handshake[4 : 4+size]
				if len(message) < 3 || u24(message[:3]) != len(message)-3 {
					return fmt.Errorf("invalid TLS 1.2 certificate list")
				}
				certs := make([]*x509.Certificate, 0)
				message = message[3:]
				for len(message) > 0 {
					if len(message) < 3 {
						return fmt.Errorf("truncated certificate length")
					}
					size := u24(message[:3])
					message = message[3:]
					if size == 0 || size > len(message) {
						return fmt.Errorf("truncated certificate")
					}
					cert, err := x509.ParseCertificate(message[:size])
					if err != nil {
						return err
					}
					certs = append(certs, cert)
					message = message[size:]
					if len(certs) > 32 {
						return fmt.Errorf("certificate chain too long")
					}
				}
				if len(certs) > 0 {
					if err := emit(certs); err != nil {
						return err
					}
				}
			}
			handshake = handshake[size+4:]
		}
	}
}
