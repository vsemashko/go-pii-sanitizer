package sanitizer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestZerologIntegration(t *testing.T) {
	s := NewDefault()

	// Create buffer to capture logs
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	// Test data with PII
	user := map[string]interface{}{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
		"amount":   100.50,
	}

	// Log with sanitized data
	logger.Info().Object("user", s.ZerologObject(user)).Msg("user action")

	output := buf.String()

	// Verify PII is redacted
	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted in zerolog output")
	}
	if strings.Contains(output, "John Doe") {
		t.Error("Expected name to be redacted in zerolog output")
	}

	// Verify safe fields are preserved
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected orderId to be preserved in zerolog output")
	}
}

func TestZerologObject(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	user := map[string]interface{}{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}

	logger.Info().Object("user", s.ZerologObject(user)).Msg("test")

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected orderId to be preserved")
	}
}

func TestZerologString(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	// Use ZerologString helper
	key, value := s.ZerologString("email", "user@example.com")
	logger.Info().Str(key, value).Msg("test")

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Error("Expected [REDACTED] in output")
	}
}

func TestZerologNested(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

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

	logger.Info().Object("data", s.ZerologObject(data)).Msg("complex data")

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

func TestZerologSlice(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"email":   "user1@example.com",
				"orderId": "ORD-1",
			},
			map[string]interface{}{
				"email":   "user2@example.com",
				"orderId": "ORD-2",
			},
		},
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("users")

	output := buf.String()

	// Emails should be redacted
	if strings.Contains(output, "user1@example.com") {
		t.Error("Expected user1 email to be redacted")
	}
	if strings.Contains(output, "user2@example.com") {
		t.Error("Expected user2 email to be redacted")
	}

	// OrderIDs should be preserved
	if !strings.Contains(output, "ORD-1") {
		t.Error("Expected ORD-1 to be preserved")
	}
	if !strings.Contains(output, "ORD-2") {
		t.Error("Expected ORD-2 to be preserved")
	}
}

func TestZerologStruct(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

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

	logger.Info().Object("data", s.ZerologObject(user)).Msg("user")

	output := buf.String()

	// Email should be redacted
	if strings.Contains(output, "user@example.com") {
		t.Error("Expected email to be redacted")
	}

	// OrderID should be preserved
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected OrderID to be preserved")
	}
}

func TestZerologMixedTypes(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]interface{}{
		"string":  "user@example.com",
		"int":     12345,
		"float":   99.99,
		"bool":    true,
		"null":    nil,
		"orderId": "ORD-123",
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("test")

	// Parse JSON to check values
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	dataMap := logEntry["data"].(map[string]interface{})

	// String with PII should be redacted
	if dataMap["string"] == "user@example.com" {
		t.Error("Expected email string to be redacted")
	}

	// Non-string types should be preserved
	if dataMap["int"] != float64(12345) { // JSON numbers are float64
		t.Errorf("Expected int to be preserved, got %v", dataMap["int"])
	}
	if dataMap["float"] != 99.99 {
		t.Error("Expected float to be preserved")
	}
	if dataMap["bool"] != true {
		t.Error("Expected bool to be preserved")
	}
	if dataMap["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestZerologArrays(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]interface{}{
		"emails": []interface{}{
			"user1@example.com",
			"user2@example.com",
			"not-an-email",
		},
		"numbers": []interface{}{
			1, 2, 3,
		},
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("arrays")

	output := buf.String()

	// Emails should be redacted
	if strings.Contains(output, "user1@example.com") {
		t.Error("Expected user1@example.com to be redacted")
	}
	if strings.Contains(output, "user2@example.com") {
		t.Error("Expected user2@example.com to be redacted")
	}

	// Non-PII string should be preserved
	if !strings.Contains(output, "not-an-email") {
		t.Error("Expected not-an-email to be preserved")
	}

	// Numbers should be preserved
	if !strings.Contains(output, "1") || !strings.Contains(output, "2") || !strings.Contains(output, "3") {
		t.Error("Expected numbers to be preserved")
	}
}

func TestZerologDeepNesting(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": map[string]interface{}{
					"email":   "user@example.com",
					"orderId": "ORD-123",
				},
			},
		},
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("deep")

	output := buf.String()

	if strings.Contains(output, "user@example.com") {
		t.Error("Expected deeply nested email to be redacted")
	}
	if !strings.Contains(output, "ORD-123") {
		t.Error("Expected deeply nested orderId to be preserved")
	}
}

func TestZerologRegionalPatterns(t *testing.T) {
	s := NewForRegion(Singapore, Malaysia, UAE)

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]interface{}{
		"nric":  "S1234567A",
		"mykad": "901230-14-5678",
		"iban":  "AE07 0331 2345 6789 0123 456",
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("regional")

	output := buf.String()

	// All regional patterns should be redacted
	if strings.Contains(output, "S1234567A") {
		t.Error("Expected Singapore NRIC to be redacted")
	}
	if strings.Contains(output, "901230-14-5678") {
		t.Error("Expected Malaysia MyKad to be redacted")
	}
	if strings.Contains(output, "AE07 0331 2345 6789 0123 456") {
		t.Error("Expected UAE IBAN to be redacted")
	}
}

func TestZerologPartialMasking(t *testing.T) {
	config := NewDefaultConfig().
		WithStrategy(StrategyPartial).
		WithPartialMasking('*', 0, 4)
	s := New(config)

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]interface{}{
		"creditCard": "4532-1234-5678-9010",
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("partial")

	output := buf.String()

	// Should contain partial masking
	if strings.Contains(output, "4532-1234-5678-9010") {
		t.Error("Expected credit card to be partially masked")
	}
	if !strings.Contains(output, "9010") {
		t.Error("Expected last 4 digits to be visible")
	}
}

func BenchmarkZerologObject(b *testing.B) {
	s := NewDefault()
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	user := map[string]interface{}{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		logger.Info().Object("user", s.ZerologObject(user)).Msg("test")
	}
}
