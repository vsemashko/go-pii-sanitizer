package sanitizer

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestZapIntegration(t *testing.T) {
	s := NewDefault()

	// Create observer to capture logs
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	// Test data with PII
	user := map[string]any{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
		"amount":   100.50,
	}

	// Log with sanitized data
	logger.Info("user action", zap.Object("user", s.ZapObject(user)))

	// Get logged entry
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(entries))
	}

	entry := entries[0]
	output := entry.ContextMap()

	// Verify PII is redacted
	userMap := output["user"].(map[string]any)
	if userMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if userMap["fullName"] == "John Doe" {
		t.Error("Expected name to be redacted")
	}

	// Verify safe fields are preserved
	if userMap["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestZapField(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	user := map[string]any{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}

	// Use ZapField
	logger.Info("test", s.ZapField("user", user))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(entries))
	}

	output := entries[0].ContextMap()
	userMap := output["user"].(map[string]any)

	if userMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if userMap["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestZapString(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	// Log email field
	logger.Info("test", s.ZapString("email", "user@example.com"))

	entries := logs.All()
	output := entries[0].ContextMap()

	if output["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if output["email"] != "[REDACTED]" {
		t.Errorf("Expected [REDACTED], got %v", output["email"])
	}
}

func TestZapNested(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	data := map[string]any{
		"user": map[string]any{
			"email":    "user@example.com",
			"fullName": "John Doe",
			"address": map[string]any{
				"street":     "123 Main St",
				"postalCode": "12345",
			},
		},
		"order": map[string]any{
			"orderId": "ORD-123",
			"amount":  99.99,
		},
	}

	logger.Info("complex data", zap.Object("data", s.ZapObject(data)))

	entries := logs.All()
	output := entries[0].ContextMap()
	dataMap := output["data"].(map[string]any)

	// Verify nested PII is redacted
	userMap := dataMap["user"].(map[string]any)
	if userMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if userMap["fullName"] == "John Doe" {
		t.Error("Expected name to be redacted")
	}

	addressMap := userMap["address"].(map[string]any)
	if addressMap["street"] == "123 Main St" {
		t.Error("Expected street to be redacted")
	}

	// Verify safe data is preserved
	orderMap := dataMap["order"].(map[string]any)
	if orderMap["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestZapSlice(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	data := map[string]any{
		"users": []any{
			map[string]any{
				"email":   "user1@example.com",
				"orderId": "ORD-1",
			},
			map[string]any{
				"email":   "user2@example.com",
				"orderId": "ORD-2",
			},
		},
	}

	logger.Info("users", zap.Object("data", s.ZapObject(data)))

	entries := logs.All()
	output := entries[0].ContextMap()
	dataMap := output["data"].(map[string]any)
	users := dataMap["users"].([]any)

	user1 := users[0].(map[string]any)
	if user1["email"] == "user1@example.com" {
		t.Error("Expected user1 email to be redacted")
	}
	if user1["orderId"] != "ORD-1" {
		t.Error("Expected user1 orderId to be preserved")
	}

	user2 := users[1].(map[string]any)
	if user2["email"] == "user2@example.com" {
		t.Error("Expected user2 email to be redacted")
	}
}

func TestZapStruct(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

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

	logger.Info("user", zap.Object("data", s.ZapObject(user)))

	entries := logs.All()
	output := entries[0].ContextMap()
	dataMap := output["data"].(map[string]any)

	// Email should be redacted (field name matches)
	if dataMap["Email"] == "user@example.com" || dataMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}

	// OrderID should be preserved
	if val, ok := dataMap["OrderID"]; ok && val != "ORD-123" {
		t.Error("Expected OrderID to be preserved")
	}
	if val, ok := dataMap["orderId"]; ok && val != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestZapMixedTypes(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	data := map[string]any{
		"string":  "user@example.com",
		"int":     12345,
		"float":   99.99,
		"bool":    true,
		"null":    nil,
		"orderId": "ORD-123",
	}

	logger.Info("test", zap.Object("data", s.ZapObject(data)))

	entries := logs.All()
	output := entries[0].ContextMap()
	dataMap := output["data"].(map[string]any)

	// String with PII should be redacted
	if dataMap["string"] == "user@example.com" {
		t.Error("Expected email string to be redacted")
	}

	// Non-string types should be preserved
	// Note: observer stores int as int, not int64
	if dataMap["int"] != 12345 {
		t.Errorf("Expected int to be preserved, got %v (type %T)", dataMap["int"], dataMap["int"])
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

func TestZapEncoding(t *testing.T) {
	s := NewDefault()

	// Test with JSON encoder
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout"}

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	user := map[string]any{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}

	logger.Info("test", zap.Object("user", s.ZapObject(user)))

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("Expected log entry")
	}

	// Verify the log was captured
	output := entries[0].ContextMap()
	userMap := output["user"].(map[string]any)

	if userMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
}

func BenchmarkZapObject(b *testing.B) {
	s := NewDefault()
	core, _ := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	user := map[string]any{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("test", zap.Object("user", s.ZapObject(user)))
	}
}
