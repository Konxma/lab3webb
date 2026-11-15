package notification

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestIncidentMIME(t *testing.T) {
	const subject = "Критичний інцидент"
	const recipient = "duty-engineer@internal.net"
	incident := Incident{
		Message: `Аварія <script>alert(1)</script>`, CommonName: "dispatcher-agent-01",
		Serial: "a123b456", RemoteAddr: "127.0.0.1:51111",
		ReceivedAt: time.Date(2026, 11, 15, 8, 30, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2027, 11, 15, 8, 30, 0, 0, time.UTC),
	}
	data, err := buildMessage("gateway@internal.net", recipient, subject, incident)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	subjectDecoded, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subjectDecoded != subject || message.Header.Get("To") != recipient || message.Header.Get("From") != "gateway@internal.net" {
		t.Fatalf("Unexpected MIME headers: %v (%v)", message.Header, err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" || params["boundary"] == "" {
		t.Fatalf("Invalid multipart type: %s %v (%v)", mediaType, params, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	html, err := reader.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(html))
	if err != nil || html.Header.Get("Content-Transfer-Encoding") != "quoted-printable" ||
		!strings.Contains(html.Header.Get("Content-Type"), "text/html") ||
		!bytes.Contains(body, []byte(`&lt;script&gt;`)) || !bytes.Contains(body, []byte(incident.CommonName)) ||
		bytes.Contains(body, []byte(`<script>`)) {
		t.Fatalf("Invalid escaped HTML part: %s (%v)", body, err)
	}
	attachment, err := reader.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	disposition, params, err := mime.ParseMediaType(attachment.Header.Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || params["filename"] != Filename || attachment.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatalf("Invalid attachment: %v (%v)", attachment.Header, err)
	}
	encoded, err := io.ReadAll(attachment)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(encoded, []byte("\r\n")) {
		if len(line) > 76 {
			t.Fatalf("Base64 line exceeds 76 characters: %d", len(line))
		}
	}
	report, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil || !bytes.Contains(report, []byte(incident.Message)) || !bytes.Contains(report, []byte(incident.Serial)) {
		t.Fatalf("Invalid incident report: %s (%v)", report, err)
	}
	if _, err := reader.NextPart(); !errors.Is(err, io.EOF) {
		t.Fatalf("Expected closing MIME boundary: %v", err)
	}
}

func TestRejectHeaderInjection(t *testing.T) {
	for _, fields := range [][3]string{
		{"gateway@internal.net", "duty@internal.net\r\nCc: injected@example.net", "Incident"},
		{"gateway@internal.net", "duty@internal.net", "Incident\nBcc: injected@example.net"},
	} {
		if _, err := buildMessage(fields[0], fields[1], fields[2], Incident{}); err == nil {
			t.Fatal("Header injection accepted")
		}
	}
}
