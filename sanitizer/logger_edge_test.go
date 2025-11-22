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
		slice []interface{}
	}{
		{
			name:  "Empty slice",
			slice: []interface{}{},
		},
		{
			name:  "Slice with nil",
			slice: []interface{}{nil, "test", nil},
		},
		{
			name: "Slice with maps",
			slice: []interface{}{
				map[string]interface{}{"email": "user@example.com"},
				map[string]interface{}{"phone": "+6591234567"},
			},
		},
		{
			name:  "Slice with primitives",
			slice: []interface{}{1, 2.5, true, "string"},
		},
		{
			name: "Slice with nested slices",
			slice: []interface{}{
				[]interface{}{"nested1", "nested2"},
				[]interface{}{"nested3"},
			},
		},
		{
			name: "Slice with mixed nested types",
			slice: []interface{}{
				map[string]interface{}{"key": "value"},
				[]interface{}{"item1", "item2"},
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
			data := map[string]interface{}{
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
		data map[string]interface{}
	}{
		{
			name: "Map with nil values",
			data: map[string]interface{}{
				"key1": nil,
				"key2": "value",
			},
		},
		{
			name: "Map with complex nested structures",
			data: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"level3": "deep value",
					},
				},
			},
		},
		{
			name: "Map with slices of maps",
			data: map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{"id": 1},
					map[string]interface{}{"id": 2},
				},
			},
		},
		{
			name: "Map with boolean and numeric types",
			data: map[string]interface{}{
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
		value interface{}
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

			data := map[string]interface{}{
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
		value interface{}
	}{
		{
			name:  "Nil value",
			key:   "nil_field",
			value: nil,
		},
		{
			name:  "Empty slice",
			key:   "empty_slice",
			value: []interface{}{},
		},
		{
			name:  "Empty map",
			key:   "empty_map",
			value: map[string]interface{}{},
		},
		{
			name:  "Nested empty structures",
			key:   "nested_empty",
			value: map[string]interface{}{
				"empty_slice": []interface{}{},
				"empty_map":   map[string]interface{}{},
			},
		},
		{
			name:  "Slice with channel (unsupported)",
			key:   "slice_with_channel",
			value: []interface{}{make(chan int)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := zerolog.New(buf)

			data := map[string]interface{}{
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

	testData := map[string]interface{}{
		"items": []interface{}{
			[]interface{}{
				[]interface{}{"deep", "nesting"},
			},
			map[string]interface{}{
				"nested": []interface{}{"item1", "item2"},
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

	testData := map[string]interface{}{
		"user": map[string]interface{}{
			"email": "user@example.com",
			"profile": map[string]interface{}{
				"name": "John Doe",
				"contacts": []interface{}{
					map[string]interface{}{"type": "email", "value": "john@example.com"},
					map[string]interface{}{"type": "phone", "value": "+6591234567"},
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
		value interface{}
	}{
		{
			name:  "Nil value",
			key:   "nil",
			value: nil,
		},
		{
			name: "Deeply nested map",
			key:  "deep",
			value: map[string]interface{}{
				"l1": map[string]interface{}{
					"l2": map[string]interface{}{
						"l3": "value",
					},
				},
			},
		},
		{
			name: "Mixed slice",
			key:  "mixed",
			value: []interface{}{
				1,
				"string",
				map[string]interface{}{"key": "value"},
				[]interface{}{"nested"},
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

	data := map[string]interface{}{
		"public": "safe data",
		"user": map[string]interface{}{
			"email": "user@example.com",
			"orders": []interface{}{
				map[string]interface{}{
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
