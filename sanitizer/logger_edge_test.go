package sanitizer

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Edge case tests for logger integrations to improve coverage

func TestZapMarshalSlice_MixedTypes(t *testing.T) {
	s := NewDefault()

	testCases := []struct {
		name  string
		slice []any
	}{
		{
			name:  "Empty slice",
			slice: []any{},
		},
		{
			name:  "Slice with nil",
			slice: []any{nil, "test", nil},
		},
		{
			name: "Slice with maps",
			slice: []any{
				map[string]any{"email": "user@example.com"},
				map[string]any{"phone": "+6591234567"},
			},
		},
		{
			name:  "Slice with primitives",
			slice: []any{1, 2.5, true, "string"},
		},
		{
			name: "Slice with nested slices",
			slice: []any{
				[]any{"nested1", "nested2"},
				[]any{"nested3"},
			},
		},
		{
			name: "Slice with mixed nested types",
			slice: []any{
				map[string]any{"key": "value"},
				[]any{"item1", "item2"},
				"plain string",
				42,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create an in-memory encoder
			enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
			buf := &bytes.Buffer{}
			writer := zapcore.AddSync(buf)
			core := zapcore.NewCore(enc, writer, zapcore.DebugLevel)
			logger := zap.New(core)

			// Test by wrapping slice in a map
			data := map[string]any{
				"items": tc.slice,
			}

			// Marshal using public API
			logger.Info("test", zap.Object("data", s.ZapObject(data)))

			// Check that it doesn't panic
			if buf.Len() == 0 {
				t.Error("Expected output from zap logger")
			}
		})
	}
}

func TestZapMarshalMap_EdgeCases(t *testing.T) {
	s := NewDefault()

	testCases := []struct {
		name string
		data map[string]any
	}{
		{
			name: "Map with nil values",
			data: map[string]any{
				"key1": nil,
				"key2": "value",
			},
		},
		{
			name: "Map with complex nested structures",
			data: map[string]any{
				"level1": map[string]any{
					"level2": map[string]any{
						"level3": "deep value",
					},
				},
			},
		},
		{
			name: "Map with slices of maps",
			data: map[string]any{
				"items": []any{
					map[string]any{"id": 1},
					map[string]any{"id": 2},
				},
			},
		},
		{
			name: "Map with boolean and numeric types",
			data: map[string]any{
				"active":  true,
				"count":   42,
				"balance": 99.99,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
			buf := &bytes.Buffer{}
			writer := zapcore.AddSync(buf)
			core := zapcore.NewCore(enc, writer, zapcore.DebugLevel)
			logger := zap.New(core)

			logger.Info("test", zap.Object("data", s.ZapObject(tc.data)))

			if buf.Len() == 0 {
				t.Error("Expected output from zap logger")
			}
		})
	}
}

func TestZapAddField_UnsupportedTypes(t *testing.T) {
	s := NewDefault()

	testCases := []struct {
		name  string
		key   string
		value any
	}{
		{
			name:  "Channel type",
			key:   "channel",
			value: make(chan int),
		},
		{
			name:  "Function type",
			key:   "func",
			value: func() {},
		},
		{
			name:  "Complex number",
			key:   "complex",
			value: complex(1, 2),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
			buf := &bytes.Buffer{}
			writer := zapcore.AddSync(buf)
			core := zapcore.NewCore(enc, writer, zapcore.DebugLevel)
			logger := zap.New(core)

			data := map[string]any{
				tc.key: tc.value,
			}

			// Should not panic with unsupported types
			logger.Info("test", zap.Object("data", s.ZapObject(data)))

			if buf.Len() == 0 {
				t.Error("Expected output from zap logger")
			}
		})
	}
}

func TestZerologAddField_EdgeCases(t *testing.T) {
	s := NewDefault()

	testCases := []struct {
		name  string
		key   string
		value any
	}{
		{
			name:  "Nil value",
			key:   "nil_field",
			value: nil,
		},
		{
			name:  "Empty slice",
			key:   "empty_slice",
			value: []any{},
		},
		{
			name:  "Empty map",
			key:   "empty_map",
			value: map[string]any{},
		},
		{
			name: "Nested empty structures",
			key:  "nested_empty",
			value: map[string]any{
				"empty_slice": []any{},
				"empty_map":   map[string]any{},
			},
		},
		{
			name:  "Slice with channel (unsupported)",
			key:   "slice_with_channel",
			value: []any{make(chan int)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := zerolog.New(buf)

			data := map[string]any{
				tc.key: tc.value,
			}

			// Should not panic
			logger.Info().Object("data", s.ZerologObject(data)).Msg("test")

			if buf.Len() == 0 {
				t.Error("Expected output from zerolog logger")
			}
		})
	}
}

func TestZerologArray_NestedSlices(t *testing.T) {
	s := NewDefault()

	buf := &bytes.Buffer{}
	logger := zerolog.New(buf)

	testData := map[string]any{
		"items": []any{
			[]any{
				[]any{"deep", "nesting"},
			},
			map[string]any{
				"nested": []any{"item1", "item2"},
			},
		},
	}

	logger.Info().Object("data", s.ZerologObject(testData)).Msg("test")

	if buf.Len() == 0 {
		t.Error("Expected output from zerolog logger")
	}
}

func TestZerologDict_ComplexNesting(t *testing.T) {
	s := NewDefault()

	buf := &bytes.Buffer{}
	logger := zerolog.New(buf)

	testData := map[string]any{
		"user": map[string]any{
			"email": "user@example.com",
			"profile": map[string]any{
				"name": "John Doe",
				"contacts": []any{
					map[string]any{"type": "email", "value": "john@example.com"},
					map[string]any{"type": "phone", "value": "+6591234567"},
				},
			},
		},
	}

	logger.Info().Dict("data", s.ZerologDict(testData)).Msg("test")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from zerolog logger")
	}

	// Verify PII was redacted
	if bytes.Contains(buf.Bytes(), []byte("user@example.com")) {
		t.Error("Expected email to be redacted in output")
	}
}

func TestSlogAttr_WithComplexTypes(t *testing.T) {
	s := NewDefault()

	testCases := []struct {
		name  string
		key   string
		value any
	}{
		{
			name:  "Nil value",
			key:   "nil",
			value: nil,
		},
		{
			name: "Deeply nested map",
			key:  "deep",
			value: map[string]any{
				"l1": map[string]any{
					"l2": map[string]any{
						"l3": "value",
					},
				},
			},
		},
		{
			name: "Mixed slice",
			key:  "mixed",
			value: []any{
				1,
				"string",
				map[string]any{"key": "value"},
				[]any{"nested"},
			},
		},
		{
			name:  "Channel (unsupported)",
			key:   "channel",
			value: make(chan int),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic
			attr := s.SlogAttr(tc.key, tc.value)
			if attr.Key != tc.key {
				t.Errorf("Expected key %q, got %q", tc.key, attr.Key)
			}
		})
	}
}

func TestZapObject_WithPIIInNestedStructures(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"public": "safe data",
		"user": map[string]any{
			"email": "user@example.com",
			"orders": []any{
				map[string]any{
					"orderId":     "ORD-123",
					"description": "Payment for John Doe", // Name in description
				},
			},
		},
	}

	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	buf := &bytes.Buffer{}
	writer := zapcore.AddSync(buf)
	core := zapcore.NewCore(enc, writer, zapcore.DebugLevel)
	logger := zap.New(core)

	logger.Info("test", zap.Object("data", s.ZapObject(data)))

	// Verify PII was redacted
	if bytes.Contains(buf.Bytes(), []byte("user@example.com")) {
		t.Error("Expected email to be redacted")
	}

	// Verify safe data was preserved
	if !bytes.Contains(buf.Bytes(), []byte("ORD-123")) {
		t.Error("Expected order ID to be preserved")
	}
}
