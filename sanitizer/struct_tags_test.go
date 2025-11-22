package sanitizer

import (
	"testing"
)

func TestSanitizeStructWithTags_BasicTags(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email    string `json:"email" pii:"redact"`
		FullName string `json:"fullName" pii:"redact"`
		OrderID  string `json:"orderId" pii:"preserve"`
		Age      int    `json:"age"`
	}

	user := User{
		Email:    "user@example.com",
		FullName: "John Doe",
		OrderID:  "ORD-123",
		Age:      30,
	}

	result := s.SanitizeStructWithTags(user)

	// Fields with pii:"redact" should be redacted
	if result["email"] != "[REDACTED]" {
		t.Errorf("Expected email to be redacted, got %v", result["email"])
	}
	if result["fullName"] != "[REDACTED]" {
		t.Errorf("Expected fullName to be redacted, got %v", result["fullName"])
	}

	// Fields with pii:"preserve" should be preserved
	if result["orderId"] != "ORD-123" {
		t.Errorf("Expected orderId to be preserved, got %v", result["orderId"])
	}

	// Fields without tags use pattern matching
	if result["age"] != 30 {
		t.Errorf("Expected age to be preserved, got %v", result["age"])
	}
}

func TestSanitizeStructWithTags_PreservePriority(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email       string `json:"email" pii:"preserve"` // Preserve despite matching email pattern
		Description string `json:"description" pii:"preserve"`
	}

	user := User{
		Email:       "user@example.com",
		Description: "Contains PII: user@example.com",
	}

	result := s.SanitizeStructWithTags(user)

	// pii:"preserve" takes priority over pattern matching
	if result["email"] != "user@example.com" {
		t.Errorf("Expected email to be preserved (pii:preserve), got %v", result["email"])
	}
	if result["description"] != "Contains PII: user@example.com" {
		t.Errorf("Expected description to be preserved, got %v", result["description"])
	}
}

func TestSanitizeStructWithTags_SensitiveFlag(t *testing.T) {
	s := NewDefault()

	type User struct {
		Password string `json:"password" pii:"redact,sensitive"`
		Notes    string `json:"notes" pii:"redact,sensitive"`
	}

	user := User{
		Password: "secret123",
		Notes:    "Sensitive information here",
	}

	result := s.SanitizeStructWithTags(user)

	// Both should be redacted (sensitive flag doesn't change behavior, just marks intent)
	if result["password"] != "[REDACTED]" {
		t.Error("Expected password to be redacted")
	}
	if result["notes"] != "[REDACTED]" {
		t.Error("Expected notes to be redacted")
	}
}

func TestSanitizeStructWithTags_NestedStructs(t *testing.T) {
	s := NewDefault()

	type Address struct {
		Street string `json:"street" pii:"redact"`
		City   string `json:"city" pii:"preserve"`
	}

	type User struct {
		Name    string  `json:"name" pii:"redact"`
		Address Address `json:"address"`
		OrderID string  `json:"orderId" pii:"preserve"`
	}

	user := User{
		Name: "John Doe",
		Address: Address{
			Street: "123 Main St",
			City:   "Singapore",
		},
		OrderID: "ORD-123",
	}

	result := s.SanitizeStructWithTags(user)

	// Top-level field
	if result["name"] != "[REDACTED]" {
		t.Error("Expected name to be redacted")
	}

	// Nested struct
	addr, ok := result["address"].(map[string]any)
	if !ok {
		t.Fatal("Expected address to be a map")
	}

	if addr["street"] != "[REDACTED]" {
		t.Error("Expected nested street to be redacted")
	}
	if addr["city"] != "Singapore" {
		t.Errorf("Expected nested city to be preserved, got %v", addr["city"])
	}

	if result["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestSanitizeStructWithTags_Slices(t *testing.T) {
	s := NewDefault()

	type User struct {
		Emails []string `json:"emails" pii:"redact"`
		Tags   []string `json:"tags" pii:"preserve"`
	}

	user := User{
		Emails: []string{"user1@example.com", "user2@example.com"},
		Tags:   []string{"premium", "verified"},
	}

	result := s.SanitizeStructWithTags(user)

	// Slices with pii:"redact" - redact entire field
	if result["emails"] != "[REDACTED]" {
		t.Errorf("Expected emails slice to be redacted, got %v", result["emails"])
	}

	// Slices with pii:"preserve"
	tags, ok := result["tags"].([]any)
	if !ok {
		t.Fatal("Expected tags to be a slice")
	}
	if len(tags) != 2 || tags[0] != "premium" || tags[1] != "verified" {
		t.Errorf("Expected tags to be preserved, got %v", tags)
	}
}

func TestSanitizeStructWithTags_Maps(t *testing.T) {
	s := NewDefault()

	type User struct {
		Metadata map[string]string `json:"metadata" pii:"preserve"`
		Secrets  map[string]string `json:"secrets" pii:"redact"`
	}

	user := User{
		Metadata: map[string]string{
			"source": "web",
			"email":  "user@example.com", // Would normally be redacted
		},
		Secrets: map[string]string{
			"apiKey": "secret123",
		},
	}

	result := s.SanitizeStructWithTags(user)

	// Map with pii:"preserve" - preserve but still sanitize contents based on patterns
	metadata, ok := result["metadata"].(map[string]any)
	if !ok {
		t.Fatal("Expected metadata to be a map")
	}
	if metadata["source"] != "web" {
		t.Error("Expected source to be preserved")
	}
	// Email field in map should still be redacted by pattern matching
	if metadata["email"] == "user@example.com" {
		t.Error("Expected email in metadata to be redacted by pattern matching")
	}

	// Map with pii:"redact"
	if result["secrets"] != "[REDACTED]" {
		t.Errorf("Expected secrets map to be redacted, got %v", result["secrets"])
	}
}

func TestSanitizeStructWithTags_MixedTypes(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email   string  `json:"email" pii:"redact"`
		Active  bool    `json:"active"`
		Balance float64 `json:"balance" pii:"preserve"`
		Count   int     `json:"count"`
		OrderID string  `json:"orderId" pii:"preserve"`
	}

	user := User{
		Email:   "user@example.com",
		Active:  true,
		Balance: 1234.56,
		Count:   42,
		OrderID: "ORD-999",
	}

	result := s.SanitizeStructWithTags(user)

	if result["email"] != "[REDACTED]" {
		t.Error("Expected email to be redacted")
	}
	if result["active"] != true {
		t.Error("Expected active to be preserved")
	}
	if result["balance"] != 1234.56 {
		t.Error("Expected balance to be preserved (pii:preserve)")
	}
	if result["count"] != 42 {
		t.Error("Expected count to be preserved")
	}
	if result["orderId"] != "ORD-999" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestSanitizeStructWithTags_NoTags(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email    string `json:"email"`
		FullName string `json:"fullName"` // fullName matches name pattern
		OrderID  string `json:"orderId"`
	}

	user := User{
		Email:    "user@example.com",
		FullName: "John Doe",
		OrderID:  "ORD-123",
	}

	result := s.SanitizeStructWithTags(user)

	// Without tags, should use pattern matching
	if result["email"] == "user@example.com" {
		t.Error("Expected email to be redacted by pattern matching")
	}
	// "fullName" field should be redacted by pattern matching
	if result["fullName"] == "John Doe" {
		t.Error("Expected fullName to be redacted by pattern matching")
	}
	// OrderID doesn't match PII patterns
	if result["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

func TestSanitizeStructWithTags_Pointers(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email    *string `json:"email" pii:"redact"`
		OrderID  *string `json:"orderId" pii:"preserve"`
		FullName *string `json:"fullName"` // fullName matches name pattern
	}

	email := "user@example.com"
	orderId := "ORD-123"
	fullName := "John Doe"

	user := User{
		Email:    &email,
		OrderID:  &orderId,
		FullName: &fullName,
	}

	result := s.SanitizeStructWithTags(user)

	if result["email"] != "[REDACTED]" {
		t.Errorf("Expected pointer email to be redacted, got %v", result["email"])
	}
	if result["orderId"] != "ORD-123" {
		t.Error("Expected pointer orderId to be preserved")
	}
	// FullName without tag uses pattern matching
	if result["fullName"] == "John Doe" {
		t.Error("Expected pointer fullName to be redacted by pattern matching")
	}
}

func TestSanitizeStructWithTags_NilPointer(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email   *string `json:"email" pii:"redact"`
		OrderID *string `json:"orderId" pii:"preserve"`
	}

	user := User{
		Email:   nil,
		OrderID: nil,
	}

	result := s.SanitizeStructWithTags(user)

	if result["email"] != nil {
		t.Errorf("Expected nil email to remain nil, got %v", result["email"])
	}
	if result["orderId"] != nil {
		t.Errorf("Expected nil orderId to remain nil, got %v", result["orderId"])
	}
}

func TestSanitizeStructWithTags_StructPointer(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email   string `json:"email" pii:"redact"`
		OrderID string `json:"orderId" pii:"preserve"`
	}

	user := &User{
		Email:   "user@example.com",
		OrderID: "ORD-123",
	}

	result := s.SanitizeStructWithTags(user)

	if result["email"] != "[REDACTED]" {
		t.Error("Expected email to be redacted in struct pointer")
	}
	if result["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved in struct pointer")
	}
}

func TestSanitizeStructWithTags_NilStruct(t *testing.T) {
	s := NewDefault()

	var user *struct {
		Email string `pii:"redact"`
	}

	result := s.SanitizeStructWithTags(user)

	if len(result) != 0 {
		t.Errorf("Expected empty map for nil struct, got %v", result)
	}
}

func TestSanitizeStructWithTags_NonStruct(t *testing.T) {
	s := NewDefault()

	// Should fallback to regular SanitizeStruct
	result := s.SanitizeStructWithTags("not a struct")

	if len(result) != 0 {
		t.Errorf("Expected empty map for non-struct, got %v", result)
	}
}

func TestSanitizeStructWithTags_DeepNesting(t *testing.T) {
	s := NewDefault()

	type Level3 struct {
		Secret string `json:"secret" pii:"redact"`
		Public string `json:"public" pii:"preserve"`
	}

	type Level2 struct {
		Email  string `json:"email" pii:"redact"`
		Level3 Level3 `json:"level3"`
	}

	type Level1 struct {
		Name   string `json:"name" pii:"redact"`
		Level2 Level2 `json:"level2"`
	}

	data := Level1{
		Name: "John Doe",
		Level2: Level2{
			Email: "john@example.com",
			Level3: Level3{
				Secret: "top-secret",
				Public: "public-info",
			},
		},
	}

	result := s.SanitizeStructWithTags(data)

	// Level 1
	if result["name"] != "[REDACTED]" {
		t.Error("Expected level1 name to be redacted")
	}

	// Level 2
	level2, ok := result["level2"].(map[string]any)
	if !ok {
		t.Fatal("Expected level2 to be a map")
	}
	if level2["email"] != "[REDACTED]" {
		t.Error("Expected level2 email to be redacted")
	}

	// Level 3
	level3, ok := level2["level3"].(map[string]any)
	if !ok {
		t.Fatal("Expected level3 to be a map")
	}
	if level3["secret"] != "[REDACTED]" {
		t.Error("Expected level3 secret to be redacted")
	}
	if level3["public"] != "public-info" {
		t.Error("Expected level3 public to be preserved")
	}
}

func TestSanitizeStructWithTags_WithExplicitConfig(t *testing.T) {
	// Config with explicit redact/preserve lists
	config := NewDefaultConfig().
		WithRedact("customField").
		WithPreserve("email") // Override pattern matching

	s := New(config)

	type User struct {
		Email       string `json:"email"`                      // No tag, but in config preserve list
		CustomField string `json:"customField" pii:"preserve"` // Tag preserve overrides config redact
		FullName    string `json:"fullName" pii:"redact"`
	}

	user := User{
		Email:       "user@example.com",
		CustomField: "custom-value",
		FullName:    "John Doe",
	}

	result := s.SanitizeStructWithTags(user)

	// Tag preserve has highest priority
	if result["customField"] != "custom-value" {
		t.Error("Expected customField to be preserved (tag overrides config)")
	}

	// Config preserve list
	if result["email"] != "user@example.com" {
		t.Errorf("Expected email to be preserved by config, got %v", result["email"])
	}

	// Tag redact
	if result["fullName"] != "[REDACTED]" {
		t.Error("Expected fullName to be redacted")
	}
}

func TestParsePIITag(t *testing.T) {
	tests := []struct {
		name      string
		tag       string
		wantNil   bool
		action    string
		sensitive bool
	}{
		{
			name:    "Empty tag",
			tag:     "",
			wantNil: true,
		},
		{
			name:      "Redact only",
			tag:       "redact",
			action:    "redact",
			sensitive: false,
		},
		{
			name:      "Preserve only",
			tag:       "preserve",
			action:    "preserve",
			sensitive: false,
		},
		{
			name:      "Redact with sensitive",
			tag:       "redact,sensitive",
			action:    "redact",
			sensitive: true,
		},
		{
			name:      "Preserve with sensitive",
			tag:       "preserve,sensitive",
			action:    "preserve",
			sensitive: true,
		},
		{
			name:      "With spaces",
			tag:       "redact, sensitive",
			action:    "redact",
			sensitive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePIITag(tt.tag)

			if tt.wantNil {
				if result != nil {
					t.Errorf("Expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.action != tt.action {
				t.Errorf("Expected action=%q, got %q", tt.action, result.action)
			}

			if result.sensitive != tt.sensitive {
				t.Errorf("Expected sensitive=%v, got %v", tt.sensitive, result.sensitive)
			}
		})
	}
}
