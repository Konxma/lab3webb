package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"time"

	"secure-alert-gateway/internal/gateway"
	"secure-alert-gateway/internal/pki"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:8443", "alert gateway address")
	dir := flag.String("certs", "certs", "directory with client certificates")
	ca := flag.String("ca", "", "trusted gateway CA file; defaults to ca.crt in -certs")
	withoutCert := flag.Bool("no-cert", false, "omit the client certificate to test TLS rejection")
	message := flag.String("message", "CRITICAL_ERROR: Database connection timeout on node-04.", "one line of UTF-8 alert text")
	flag.Parse()
	if !gateway.ValidAlert(*message) {
		return fmt.Errorf("message must contain one nonempty line of up to %d UTF-8 bytes", gateway.MaxAlertBytes)
	}
	if *ca == "" {
		*ca = filepath.Join(*dir, "ca.crt")
	}
	pool, err := pki.Roots(*ca)
	if err != nil {
		return err
	}
	config := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if !*withoutCert {
		pair, err := pki.KeyPair(*dir, "client")
		if err != nil {
			return err
		}
		config.Certificates = []tls.Certificate{pair}
		// Offer the configured certificate so the negative test can exercise server-side trust checking.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", *addr, config)
	if err != nil {
		return fmt.Errorf("TLS connection: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Printf("Gateway certificate verified (%s)\n", tls.VersionName(conn.ConnectionState().Version))
	fmt.Printf("Alert: %s\n", *message)
	if _, err := fmt.Fprintln(conn, *message); err != nil {
		return fmt.Errorf("send alert: %w", err)
	}
	line, err := bufio.NewReaderSize(conn, 256).ReadSlice('\n')
	if err != nil {
		return fmt.Errorf("read gateway reply: %w", err)
	}
	ack := strings.TrimRight(string(line), "\r\n")
	fmt.Println(ack)
	return gateway.RequireSuccess(ack)
}
