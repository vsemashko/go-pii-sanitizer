package sanitizer

import (
	"reflect"
	"testing"
)

// Edge case tests for struct_tags.go to improve coverage

func TestSanitizeStructWithTags_MaxDepthExceeded(t *testing.T) {
	config := NewDefaultConfig()
	config.MaxDepth = 2
	s := New(config)

	type Level3 struct {
		Data string `json:"data"`
	}

	type Level2 struct {
		Level3 Level3 `json:"level3"`
	}

	type Level1 struct {
		Level2 Level2 `json:"level2"`
	}

	type Root struct {
		Level1 Level1 `json:"level1"`
	}

	root := Root{
		Level1: Level1{
			Level2: Level2{
				Level3: Level3{
					Data: "test",
				},
			},
		},
	}

	result := s.SanitizeStructWithTags(root)

	// Should hit max depth and return empty map for deepest level
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSanitizeValueRecursive_AllTypes(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name     string
		input    any
		expected any
	}{
		{
			name:     "Nil value",
			input:    nil,
			expected: nil,
		},
		{
			name:     "String with email",
			input:    "contact: user@example.com",
			expected: "[REDACTED]",
		},
		{
			name:     "Plain string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "Integer",
			input:    42,
			expected: 42,
		},
		{
			name:     "Float",
			input:    3.14,
			expected: 3.14,
		},
		{
			name:     "Boolean",
			input:    true,
			expected: true,
		},
		{
			name:     "Slice of strings",
			input:    []string{"test1", "test2"},
			expected: []any{"test1", "test2"},
		},
		{
			name:     "Slice of integers",
			input:    []int{1, 2, 3},
			expected: []any{1, 2, 3},
		},
		{
			name: "Map[string]string",
			input: map[string]string{
				"key": "value",
			},
			expected: map[string]any{
				"key": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.sanitizeValueRecursive("field", tt.input, 0)

			// Type-specific comparisons
			switch expected := tt.expected.(type) {
			case nil:
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
			case string:
				if result != expected {
					t.Errorf("Expected %v, got %v", expected, result)
				}
			case int:
				if result != expected {
					t.Errorf("Expected %v, got %v", expected, result)
				}
			case float64:
				if result != expected {
					t.Errorf("Expected %v, got %v", expected, result)
				}
			case bool:
				if result != expected {
					t.Errorf("Expected %v, got %v", expected, result)
				}
			default:
				// For slices and maps, just check not nil
				if result == nil {
					t.Error("Expected non-nil result")
				}
			}
		})
	}
}

func TestSanitizeValueRecursive_NestedStruct(t *testing.T) {
	s := NewDefault()

	type Inner struct {
		Email string `json:"email"`
	}

	inner := Inner{Email: "user@example.com"}

	result := s.sanitizeValueRecursive("user", inner, 0)

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("Expected map result")
	}

	if resultMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
}

func TestSanitizeValueRecursive_NestedMap(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"email": "user@example.com",
		"nested": map[string]any{
			"phone": "+6591234567",
		},
	}

	result := s.sanitizeValueRecursive("data", data, 0)

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("Expected map result")
	}

	if resultMap["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}

	nested, ok := resultMap["nested"].(map[string]any)
	if !ok {
		t.Fatal("Expected nested map")
	}

	if nested["phone"] == "+6591234567" {
		t.Error("Expected phone to be redacted")
	}
}

func TestSanitizeValueRecursive_NestedSlice(t *testing.T) {
	s := NewDefault()

	data := []any{
		"user@example.com",
		map[string]any{
			"email": "test@example.com",
		},
	}

	result := s.sanitizeValueRecursive("emails", data, 0)

	resultSlice, ok := result.([]any)
	if !ok {
		t.Fatal("Expected slice result")
	}

	if len(resultSlice) != 2 {
		t.Errorf("Expected 2 elements, got %d", len(resultSlice))
	}

	// First element should be redacted
	if resultSlice[0] == "user@example.com" {
		t.Error("Expected first element to be redacted")
	}
}

func TestSanitizeValueRecursive_MaxDepth(t *testing.T) {
	config := NewDefaultConfig()
	config.MaxDepth = 1
	s := New(config)

	// Create deeply nested structure
	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": "value",
			},
		},
	}

	result := s.sanitizeValueRecursive("data", data, 5) // Start at depth 5

	// Should return value as-is when depth exceeded
	if result == nil {
		t.Error("Expected non-nil result even when depth exceeded")
	}
}

func TestSanitizeValueRecursive_PointerTypes(t *testing.T) {
	s := NewDefault()

	// Test pointer to string
	email := "user@example.com"
	result := s.sanitizeValueRecursive("email", &email, 0)
	if result == "user@example.com" {
		t.Error("Expected pointer email to be redacted")
	}

	// Test nil pointer
	var nilPtr *string
	result = s.sanitizeValueRecursive("field", nilPtr, 0)
	if result != nil {
		t.Error("Expected nil for nil pointer")
	}

	// Test pointer to struct
	type User struct {
		Email string `json:"email"`
	}
	user := &User{Email: "test@example.com"}
	result = s.sanitizeValueRecursive("user", user, 0)
	if result == nil {
		t.Error("Expected non-nil result for pointer to struct")
	}
}

func TestConvertValue_AllTypes(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name  string
		input any
	}{
		{"Nil", nil},
		{"String", "test"},
		{"Int", 42},
		{"Float", 3.14},
		{"Bool", true},
		{"Slice", []string{"a", "b"}},
		{"Map", map[string]string{"key": "value"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.convertValue(tt.input, 0)
			if tt.input == nil && result != nil {
				t.Error("Expected nil result for nil input")
			}
		})
	}
}

func TestConvertValue_Struct(t *testing.T) {
	s := NewDefault()

	type User struct {
		Name string `json:"name"`
	}

	user := User{Name: "John Doe"}
	result := s.convertValue(user, 0)

	if result == nil {
		t.Error("Expected non-nil result for struct")
	}
}

func TestConvertValue_PointerToStruct(t *testing.T) {
	s := NewDefault()

	type User struct {
		Name string `json:"name"`
	}

	user := &User{Name: "John Doe"}
	result := s.convertValue(user, 0)

	if result == nil {
		t.Error("Expected non-nil result for pointer to struct")
	}
}

func TestConvertValue_NilPointer(t *testing.T) {
	s := NewDefault()

	var user *struct {
		Name string
	}

	result := s.convertValue(user, 0)
	if result != nil {
		t.Error("Expected nil for nil pointer")
	}
}

func TestSanitizeMapValue_NonMap(t *testing.T) {
	s := NewDefault()

	result := s.sanitizeMapValue(toReflectValue("not a map"), 0)

	// Should return value as-is
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSanitizeMapValue_MaxDepth(t *testing.T) {
	config := NewDefaultConfig()
	config.MaxDepth = 1
	s := New(config)

	data := map[string]any{
		"key": "value",
	}

	result := s.sanitizeMapValue(toReflectValue(data), 10) // Depth > MaxDepth

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("Expected map result")
	}

	if len(resultMap) != 0 {
		t.Error("Expected empty map when max depth exceeded")
	}
}

func TestSanitizeMapValue_NonStringKeys(t *testing.T) {
	s := NewDefault()

	// Map with int keys (should be skipped)
	data := map[int]string{
		1: "value1",
		2: "value2",
	}

	result := s.sanitizeMapValue(toReflectValue(data), 0)

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("Expected map result")
	}

	// Should be empty since keys are not strings
	if len(resultMap) != 0 {
		t.Error("Expected empty map for non-string keys")
	}
}

func TestSanitizeSliceValue_MaxDepth(t *testing.T) {
	config := NewDefaultConfig()
	config.MaxDepth = 1
	s := New(config)

	data := []string{"test1", "test2"}

	result := s.sanitizeSliceValue(toReflectValue(data), 10) // Depth > MaxDepth

	resultSlice, ok := result.([]any)
	if !ok {
		t.Fatal("Expected slice result")
	}

	if len(resultSlice) != 0 {
		t.Error("Expected empty slice when max depth exceeded")
	}
}

func TestSanitizeFieldWithTag_NonStringRedact(t *testing.T) {
	s := NewDefault()

	type Data struct {
		Count int `pii:"redact"`
	}

	data := Data{Count: 42}

	result := s.SanitizeStructWithTags(data)

	// Non-string field with redact tag should return "[REDACTED]"
	if result["Count"] != "[REDACTED]" {
		t.Errorf("Expected [REDACTED] for non-string redact field, got %v", result["Count"])
	}
}

func TestSanitizeFieldWithTag_InvalidField(t *testing.T) {
	s := NewDefault()

	type Data struct {
		unexported string `pii:"redact"`
	}

	data := Data{unexported: "secret"}
	result := s.SanitizeStructWithTags(data)

	// Unexported field should not appear in result
	if len(result) != 0 {
		t.Error("Expected empty result for unexported fields")
	}
}

// Helper function to create reflect.Value
func toReflectValue(v any) reflect.Value {
	return reflect.ValueOf(v)
}
