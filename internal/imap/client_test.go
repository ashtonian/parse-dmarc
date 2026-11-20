package imap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/rs/zerolog"
)

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "internal-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTLSConfig(t *testing.T) {
	log := zerolog.Nop()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	junkFile := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junkFile, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}

	c := &Client{log: &log, config: &config.IMAPConfig{Host: "imap.internal"}}
	cfg, err := c.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "imap.internal" || cfg.InsecureSkipVerify || cfg.RootCAs != nil {
		t.Fatalf("unexpected default tls config: %+v", cfg)
	}

	c.config = &config.IMAPConfig{Host: "imap.internal", TLSSkipVerify: true}
	if cfg, err = c.tlsConfig(); err != nil || !cfg.InsecureSkipVerify {
		t.Fatalf("skip verify not honored: %v %v", cfg, err)
	}

	c.config = &config.IMAPConfig{Host: "imap.internal", TLSCAFile: caFile}
	if cfg, err = c.tlsConfig(); err != nil || cfg.RootCAs == nil {
		t.Fatalf("CA file not loaded: %v %v", cfg, err)
	}

	c.config = &config.IMAPConfig{Host: "imap.internal", TLSCAFile: junkFile}
	if _, err = c.tlsConfig(); err == nil {
		t.Error("want error for a PEM file with no certificates")
	}

	c.config = &config.IMAPConfig{Host: "imap.internal", TLSCAFile: filepath.Join(t.TempDir(), "missing.pem")}
	if _, err = c.tlsConfig(); err == nil {
		t.Error("want error for a missing CA file")
	}
}

// firstClientBytes returns what the server sees from the client after the
// greeting, which tells implicit TLS from STARTTLS from plaintext.
func firstClientBytes(t *testing.T, cfg *config.IMAPConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host = host
	cfg.Port, err = strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}

	log := zerolog.Nop()
	c := &Client{log: &log, config: cfg}
	// The server hangs up mid-handshake, so errors here are expected; the
	// assertion is on what the client sent, not on a successful connection.
	imapClient, err := c.dial(ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test
	first := <-got
	if err == nil {
		_ = imapClient.Logout()
	}
	return first
}

func TestDialTransportSelection(t *testing.T) {
	// UseTLS defaults to true, so STARTTLS must take precedence over it.
	if got := firstClientBytes(t, &config.IMAPConfig{UseTLS: true, StartTLS: true}); !strings.Contains(strings.ToUpper(got), "STARTTLS") {
		t.Errorf("starttls: want a STARTTLS command, got %q", got)
	}
	if got := firstClientBytes(t, &config.IMAPConfig{UseTLS: true}); !strings.HasPrefix(got, "\x16") {
		t.Errorf("implicit tls: want a TLS handshake record, got %q", got)
	}
	if got := firstClientBytes(t, &config.IMAPConfig{}); got != "" {
		t.Errorf("plaintext: want no unsolicited client traffic, got %q", got)
	}
}
