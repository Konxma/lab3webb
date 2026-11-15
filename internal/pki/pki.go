package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func Generate(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("certificate directory already exists: %s", dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	work, err := os.MkdirTemp(filepath.Dir(dir), ".pki-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	now := time.Now()
	ca, err := template("Secure Alert Lab Root CA", now, now.AddDate(2, 0, 0))
	if err != nil {
		return err
	}
	ca.IsCA = true
	ca.BasicConstraintsValid = true
	ca.MaxPathLenZero = true
	ca.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	caKey, err := issue(work, "ca", ca, ca, nil)
	if err != nil {
		return err
	}

	server, err := template("localhost", now, now.AddDate(1, 0, 0))
	if err != nil {
		return err
	}
	server.DNSNames = []string{"localhost"}
	server.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err = issue(work, "server", server, ca, caKey); err != nil {
		return err
	}

	client, err := template("dispatcher-agent-01", now, now.AddDate(1, 0, 0))
	if err != nil {
		return err
	}
	client.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if _, err = issue(work, "client", client, ca, caKey); err != nil {
		return err
	}
	return os.Rename(work, dir)
}

func template(cn string, now, expires time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	serial.SetBit(serial, 128, 1)
	return &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, nil
}

func issue(dir, name string, cert, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func Roots(file string) (*x509.CertPool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no PEM certificates in %s", file)
	}
	return pool, nil
}

func KeyPair(dir, name string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"))
}
