package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestFragmentedTLSCertificateHandshake(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	body := append(encode(len(der)+3), encode(len(der))...)
	body = append(body, der...)
	handshake := append([]byte{11}, encode(len(body))...)
	handshake = append(handshake, body...)
	var records bytes.Buffer
	for _, fragment := range [][]byte{handshake[:7], handshake[7:]} {
		records.Write([]byte{22, 3, 3, byte(len(fragment) >> 8), byte(len(fragment))})
		records.Write(fragment)
	}
	matches := 0
	err = readCertificates(&records, func(certs []*x509.Certificate) error {
		matches++
		if len(certs) != 1 || !bytes.Equal(certs[0].Raw, der) {
			t.Error("certificate changed")
		}
		return nil
	})
	if err != io.EOF || matches != 1 {
		t.Fatalf("matches=%d error=%v", matches, err)
	}
}

func TestMalformedTLSLengthRejected(t *testing.T) {
	if err := readCertificates(bytes.NewReader([]byte{22, 3, 3, 255, 255}), func([]*x509.Certificate) error { return nil }); err == nil {
		t.Fatal("oversized record accepted")
	}
}
