package gateway

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"secure-alert-gateway/internal/notification"
)

const (
	MaxAlertBytes = 4096
	Verified      = "[SERVER]: ALERT RECEIVED AND VERIFIED"
	Dispatched    = "[SERVER]: ALERT PROCESSED AND DISPATCHED"
	DeliveryError = "[SERVER]: ALERT VERIFIED, EMAIL FAILED"
	InvalidAlert  = "[SERVER]: INVALID ALERT"
)

type Gateway struct {
	Logger *slog.Logger
	Sender *notification.Sender
	To     string
}

func (g Gateway) Handle(conn *tls.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		g.Logger.Warn("mTLS rejected", "remote", peer, "error", err)
		return
	}
	state := conn.ConnectionState()
	cert := state.PeerCertificates[0] // The listener requires a verified client certificate.
	incident := notification.Incident{
		CommonName: cert.Subject.CommonName,
		Serial:     cert.SerialNumber.Text(16),
		ExpiresAt:  cert.NotAfter.UTC(),
		RemoteAddr: peer,
	}
	g.Logger.Info("mTLS verified", "client_cn", incident.CommonName, "serial", incident.Serial,
		"expires_at", incident.ExpiresAt, "remote", incident.RemoteAddr, "tls", tls.VersionName(state.Version))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReaderSize(conn, MaxAlertBytes+2).ReadSlice('\n')
	message := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	if err != nil || !ValidAlert(message) {
		g.Logger.Warn("Invalid alert", "client_cn", incident.CommonName, "remote", peer, "error", err)
		g.reply(conn, InvalidAlert)
		return
	}
	incident.Message = message
	incident.ReceivedAt = time.Now().UTC()
	g.Logger.Info("Alert received", "client_cn", incident.CommonName, "incident", incident.Message, "received_at", incident.ReceivedAt)
	if g.Sender == nil {
		g.reply(conn, Verified)
		return
	}
	if err := g.Sender.Send(g.To, "Критичний інцидент | Secure Alert Gateway", incident); err != nil {
		g.Logger.Error("SMTP delivery failed", "to", g.To, "error", err)
		g.reply(conn, DeliveryError)
		return
	}
	g.Logger.Info("SMTP accepted message over STARTTLS", "to", g.To, "attachment", notification.Filename)
	g.reply(conn, Dispatched)
}

func (g Gateway) reply(conn *tls.Conn, response string) {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, response+"\n"); err != nil {
		g.Logger.Warn("Failed to reply", "remote", conn.RemoteAddr().String(), "error", err)
	}
}

func ValidAlert(message string) bool {
	return len(message) <= MaxAlertBytes && strings.TrimSpace(message) != "" &&
		utf8.ValidString(message) && !strings.ContainsFunc(message, unicode.IsControl)
}

func RequireSuccess(ack string) error {
	if ack != Verified && ack != Dispatched {
		return fmt.Errorf("gateway reported failure: %q", ack)
	}
	return nil
}
