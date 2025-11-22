package sanitizer

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestSlogIntegration(t *testing.T) {
	s := NewDefault()

	// Test data with PII
	user := map[string]interface{}{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
		"amount":   100.50,
	}

	// Create a buffer to capture log output
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// Log with sanitized data
	logger.Info("user action", "user", s.SlogValue(user))

	output := buf.String()

	// Verify PII is redacted
	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted in slog output")
	}
	if strings.Contains(output, "John Doe") {
		t.Error("Expected name to be redacted in slog output")
	}

	// Verify safe fields are preserved
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected orderId to be preserved in slog output")
	}
}

func TestSlogAttr(t *testing.T) {
	s := NewDefault()

	user := map[string]interface{}{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// Use SlogAttr
	logger.Info("test", s.SlogAttr("user", user))

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected orderId to be preserved")
	}
}

func TestSlogString(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// Log email field
	logger.Info("test", s.SlogString("email", "user@example.com"))

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Error("Expected [REDACTED] in output")
	}
}

func TestSlogGroup(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// Use SlogGroup
	logger.Info("test",
		s.SlogGroup("user",
			"email", "user@example.com",
			"orderId", "ORD-123",
		),
	)

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted in group")
	}
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected orderId to be preserved in group")
	}
}

func TestSlogNested(t *testing.T) {
	s := NewDefault()

	data := map[string]interface{}{
		"user": map[string]interface{}{
			"email":    "user@example.com",
			"fullName": "John Doe",
			"address": map[string]interface{}{
				"street":     "123 Main St",
				"postalCode": "12345",
			},
		},
		"order": map[string]interface{}{
			"orderId": "ORD-123",
			"amount":  99.99,
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	logger.Info("complex data", "data", s.SlogValue(data))

	output := buf.String()

	// PII should be redacted
	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}
	if strings.Contains(output, "John Doe") {
		t.Error("Expected name to be redacted")
	}
	if strings.Contains(output, "123 Main St") {
		t.Error("Expected street to be redacted")
	}

	// Safe data should be preserved
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected orderId to be preserved")
	}
}

func TestSlogStringContent(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// String with embedded PII
	text := "Contact me at user@example.com for details"
	logger.Info("test", "message", s.SlogValue(text))

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email in content to be redacted")
	}
}

func TestSlogStruct(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email   string
		Name    string
		OrderID string
	}

	user := User{
		Email:   "user@example.com",
		Name:    "John Doe",
		OrderID: "ORD-123",
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	logger.Info("user", "data", s.SlogValue(user))

	output := buf.String()

	// PII should be redacted (struct fields converted to lowercase in JSON)
	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}

	// OrderID should be preserved
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected OrderID to be preserved")
	}
}
