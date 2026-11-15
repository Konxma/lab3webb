package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCertificateRoles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	ca, err := Roots(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, checks := range []struct {
		role, dns string
		usage     x509.ExtKeyUsage
	}{
		{"server", "localhost", x509.ExtKeyUsageServerAuth},
		{"server", "127.0.0.1", x509.ExtKeyUsageServerAuth},
		{"client", "", x509.ExtKeyUsageClientAuth},
	} {
		pair, err := KeyPair(dir, checks.role)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: ca, DNSName: checks.dns, KeyUsages: []x509.ExtKeyUsage{checks.usage}}); err != nil {
			t.Fatal(err)
		}
		if checks.role == "client" && cert.Subject.CommonName != "dispatcher-agent-01" {
			t.Fatalf("Unexpected client CN: %s", cert.Subject.CommonName)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: ca, DNSName: "other.example"}); err == nil {
			t.Fatal("Unexpected trust for a different hostname")
		}
	}
	key := filepath.Join(dir, "ca.key")
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(dir); err == nil {
		t.Fatal("Generator overwrote the existing PKI")
	}
	after, err := os.ReadFile(key)
	if err != nil || string(before) != string(after) {
		t.Fatal("CA key changed after attempted regeneration")
	}
}
