package notification

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

const Filename = "incident_report.log"

type Incident struct {
	Message    string
	CommonName string
	Serial     string
	ExpiresAt  time.Time
	ReceivedAt time.Time
	RemoteAddr string
}

type Config struct {
	Address  string
	From     string
	Username string
	Password string
	RootCAs  *x509.CertPool
}

type Sender struct {
	config Config
	host   string
}

func NewSender(config Config) (*Sender, error) {
	host, port, err := net.SplitHostPort(config.Address)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("SMTP address must include a host and port")
	}
	if !validAddress(config.From) {
		return nil, fmt.Errorf("invalid SMTP sender address")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, fmt.Errorf("set both SMTP_USERNAME and SMTP_PASSWORD to enable SMTP authentication")
	}
	return &Sender{config: config, host: host}, nil
}

func validAddress(address string) bool {
	parsed, err := mail.ParseAddress(address)
	return err == nil && parsed.Address == address && !strings.ContainsAny(address, "\r\n")
}

func (s *Sender) Send(to, subject string, incident Incident) error {
	message, err := buildMessage(s.config.From, to, subject, incident)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", s.config.Address, 4*time.Second)
	if err != nil {
		return fmt.Errorf("connect to SMTP: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("SMTP relay does not offer STARTTLS")
	}
	if err := client.StartTLS(&tls.Config{ServerName: s.host, RootCAs: s.config.RootCAs, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("SMTP STARTTLS: %w", err)
	}
	if s.config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.config.Username, s.config.Password, s.host)); err != nil {
			return fmt.Errorf("SMTP authentication: %w", err)
		}
	}
	if err := client.Mail(s.config.From); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP did not accept the message: %w", err)
	}
	// DATA has already been accepted. A failed QUIT must not turn this into a failed delivery.
	_ = client.Quit()
	return nil
}

var alertHTML = template.Must(template.New("incident").Parse(`<!doctype html>
<html lang="uk"><meta charset="utf-8"><body style="font-family:Arial,sans-serif;color:#182934;background:#f3f6fa;padding:24px">
<div style="max-width:640px;margin:auto;border:1px solid #cbd5df;background:#fff">
  <header style="background:#981b35;color:#fff;padding:18px 24px"><h1 style="margin:0;font-size:24px">Критичний інцидент</h1></header>
  <div style="padding:12px 24px 20px">
    <p style="font-size:17px"><strong>{{.Message}}</strong></p>
    <table style="width:100%;border-collapse:collapse;text-align:left">
      <tr><th style="padding:8px 0">Час реєстрації (UTC)</th><td>{{.ReceivedAt.Format "2006-01-02 15:04:05Z07:00"}}</td></tr>
      <tr><th style="padding:8px 0">Джерело</th><td>{{.RemoteAddr}}</td></tr>
      <tr><th style="padding:8px 0">Клієнтський CN</th><td>{{.CommonName}}</td></tr>
      <tr><th style="padding:8px 0">Серійний номер</th><td style="overflow-wrap:anywhere">{{.Serial}}</td></tr>
      <tr><th style="padding:8px 0">Сертифікат дійсний до</th><td>{{.ExpiresAt.Format "2006-01-02 15:04:05Z07:00"}}</td></tr>
    </table>
  </div>
</div></body></html>`))

func buildMessage(from, to, subject string, incident Incident) ([]byte, error) {
	if !validAddress(from) || !validAddress(to) || subject == "" || strings.ContainsAny(subject, "\r\n") {
		return nil, fmt.Errorf("invalid message addressing or subject")
	}
	var message bytes.Buffer
	parts := multipart.NewWriter(&message)
	fmt.Fprintf(&message, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: %s\r\n\r\n",
		from, to, mime.QEncoding.Encode("utf-8", subject), incident.ReceivedAt.Format(time.RFC1123Z),
		mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": parts.Boundary()}))
	body, err := parts.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	html := quotedprintable.NewWriter(body)
	if err := alertHTML.Execute(html, incident); err != nil {
		return nil, err
	}
	if err := html.Close(); err != nil {
		return nil, err
	}
	attachment, err := parts.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=utf-8"},
		"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": Filename})},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	report := fmt.Sprintf("received_at=%s\r\nsource=%q\r\nclient_cn=%q\r\ncertificate_serial=%s\r\ncertificate_expires_at=%s\r\nincident=%q\r\n",
		incident.ReceivedAt.Format(time.RFC3339Nano), incident.RemoteAddr, incident.CommonName, incident.Serial,
		incident.ExpiresAt.Format(time.RFC3339), incident.Message)
	encoded := base64.StdEncoding.EncodeToString([]byte(report))
	for start := 0; start < len(encoded); start += 76 {
		if start != 0 {
			if _, err = io.WriteString(attachment, "\r\n"); err != nil {
				return nil, err
			}
		}
		if _, err = io.WriteString(attachment, encoded[start:min(start+76, len(encoded))]); err != nil {
			return nil, err
		}
	}
	if err := parts.Close(); err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}
