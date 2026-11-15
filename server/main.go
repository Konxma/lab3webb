package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"

	"secure-alert-gateway/internal/gateway"
	"secure-alert-gateway/internal/notification"
	"secure-alert-gateway/internal/pki"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("Gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	addr := flag.String("addr", "127.0.0.1:8443", "mTLS listen address")
	dir := flag.String("certs", "certs", "directory with CA and server certificates")
	smtpAddr := flag.String("smtp", "127.0.0.1:1025", "SMTP relay address with STARTTLS")
	smtpCA := flag.String("smtp-ca", "", "PEM root CA file for SMTP; empty uses lab CA for loopback and system roots otherwise")
	from := flag.String("from", "gateway@internal.net", "notification sender")
	to := flag.String("to", "duty-engineer@internal.net", "notification recipient")
	mtlsOnly := flag.Bool("mtls-only", false, "verify and acknowledge without sending email")
	flag.Parse()

	cert, err := pki.KeyPair(*dir, "server")
	if err != nil {
		return err
	}
	caFile := filepath.Join(*dir, "ca.crt")
	ca, err := pki.Roots(caFile)
	if err != nil {
		return err
	}
	handler := gateway.Gateway{Logger: logger, To: *to}
	if !*mtlsOnly {
		var relayRoots *x509.CertPool
		host, _, _ := net.SplitHostPort(*smtpAddr)
		if *smtpCA != "" {
			relayRoots, err = pki.Roots(*smtpCA)
			if err != nil {
				return err
			}
		} else if host == "localhost" || net.ParseIP(host).IsLoopback() {
			relayRoots = ca
		}
		handler.Sender, err = notification.NewSender(notification.Config{
			Address: *smtpAddr, From: *from, RootCAs: relayRoots,
			Username: os.Getenv("SMTP_USERNAME"), Password: os.Getenv("SMTP_PASSWORD"),
		})
		if err != nil {
			return err
		}
	}
	listener, err := tls.Listen("tcp", *addr, &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientCAs: ca,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	logger.Info("Secure Alert Gateway listening", "address", listener.Addr(), "smtp", *smtpAddr, "mtls_only", *mtlsOnly)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handler.Handle(conn.(*tls.Conn))
	}
}
