package sanitizer

import (
	"testing"
)

func TestSanitizeFields(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name   string
		fields map[string]string
		expect map[string]string
	}{
		{
			name: "Mixed PII and safe fields",
			fields: map[string]string{
				"email":    "user@example.com",
				"fullName": "John Doe",
				"orderId":  "ORD-123",
				"phone":    "+6591234567",
			},
			expect: map[string]string{
				"email":    "[REDACTED]",
				"fullName": "[REDACTED]",
				"orderId":  "ORD-123",
				"phone":    "[REDACTED]",
			},
		},
		{
			name:   "Empty fields",
			fields: map[string]string{},
			expect: map[string]string{},
		},
		{
			name: "All safe fields",
			fields: map[string]string{
				"orderId":   "ORD-123",
				"productId": "PROD-456",
				"quantity":  "5",
			},
			expect: map[string]string{
				"orderId":   "ORD-123",
				"productId": "PROD-456",
				"quantity":  "5",
			},
		},
		{
			name: "All PII fields",
			fields: map[string]string{
				"email":    "test@example.com",
				"fullName": "Jane Smith",
				"phone":    "+6591234567",
			},
			expect: map[string]string{
				"email":    "[REDACTED]",
				"fullName": "[REDACTED]",
				"phone":    "[REDACTED]",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := s.SanitizeFields(tc.fields)

			if len(result) != len(tc.expect) {
				t.Errorf("Expected %d fields, got %d", len(tc.expect), len(result))
			}

			for key, expectedValue := range tc.expect {
				if result[key] != expectedValue {
					t.Errorf("Field %s: expected %q, got %q", key, expectedValue, result[key])
				}
			}
		})
	}
}

func TestSanitizeBatch(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name    string
		records []map[string]any
		check   func(t *testing.T, result []map[string]any)
	}{
		{
			name: "Multiple records with PII",
			records: []map[string]any{
				{"email": "user1@example.com", "orderId": "ORD-1"},
				{"email": "user2@example.com", "orderId": "ORD-2"},
				{"email": "user3@example.com", "orderId": "ORD-3"},
			},
			check: func(t *testing.T, result []map[string]any) {
				if len(result) != 3 {
					t.Errorf("Expected 3 records, got %d", len(result))
				}
				for i, record := range result {
					if record["email"] != "[REDACTED]" {
						t.Errorf("Record %d: expected email to be [REDACTED], got %v", i, record["email"])
					}
					expectedOrderID := "ORD-" + string(rune('1'+i))
					if record["orderId"] != expectedOrderID {
						t.Errorf("Record %d: expected orderId %s, got %v", i, expectedOrderID, record["orderId"])
					}
				}
			},
		},
		{
			name:    "Empty batch",
			records: []map[string]any{},
			check: func(t *testing.T, result []map[string]any) {
				if len(result) != 0 {
					t.Errorf("Expected empty result, got %d records", len(result))
				}
			},
		},
		{
			name: "Nested structures",
			records: []map[string]any{
				{
					"user": map[string]any{
						"email":    "user@example.com",
						"fullName": "John Doe",
					},
					"orderId": "ORD-123",
				},
			},
			check: func(t *testing.T, result []map[string]any) {
				if len(result) != 1 {
					t.Errorf("Expected 1 record, got %d", len(result))
				}
				user := result[0]["user"].(map[string]any)
				if user["email"] != "[REDACTED]" {
					t.Errorf("Expected nested email to be [REDACTED], got %v", user["email"])
				}
				if user["fullName"] != "[REDACTED]" {
					t.Errorf("Expected nested fullName to be [REDACTED], got %v", user["fullName"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := s.SanitizeBatch(tc.records)
			tc.check(t, result)
		})
	}
}

func TestSanitizeFieldsWithMetrics(t *testing.T) {
	metrics := &testMetrics{}
	config := NewDefaultConfig().WithMetrics(metrics)
	s := New(config)

	fields := map[string]string{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}

	s.SanitizeFields(fields)

	// Should have recorded 2 metrics (one for each field)
	if len(metrics.calls) != 2 {
		t.Errorf("Expected 2 metric calls, got %d", len(metrics.calls))
	}

	// Check that metrics were recorded for both fields
	hasEmail := false
	hasOrderID := false
	for _, call := range metrics.calls {
		if call.FieldName == "email" {
			hasEmail = true
			if !call.Redacted {
				t.Errorf("Expected email to be redacted in metrics")
			}
		}
		if call.FieldName == "orderId" {
			hasOrderID = true
			if call.Redacted {
				t.Errorf("Expected orderId to NOT be redacted in metrics")
			}
		}
	}

	if !hasEmail {
		t.Error("Expected metrics for email field")
	}
	if !hasOrderID {
		t.Error("Expected metrics for orderId field")
	}
}

func TestSanitizeBatchWithMetrics(t *testing.T) {
	metrics := &testMetrics{}
	config := NewDefaultConfig().WithMetrics(metrics)
	s := New(config)

	records := []map[string]any{
		{"email": "user1@example.com", "orderId": "ORD-1"},
		{"email": "user2@example.com", "orderId": "ORD-2"},
	}

	s.SanitizeBatch(records)

	// Should have 4 metrics (email + orderId for each of 2 records)
	if len(metrics.calls) != 4 {
		t.Errorf("Expected 4 metric calls, got %d", len(metrics.calls))
	}

	// Count redacted vs preserved
	redactedCount := 0
	for _, call := range metrics.calls {
		if call.Redacted {
			redactedCount++
		}
	}

	// 2 emails should be redacted
	if redactedCount != 2 {
		t.Errorf("Expected 2 redacted fields, got %d", redactedCount)
	}
}

// Benchmark for batch processing
func BenchmarkSanitizeFields(b *testing.B) {
	s := NewDefault()
	fields := map[string]string{
		"email":      "user@example.com",
		"fullName":   "John Doe",
		"orderId":    "ORD-123",
		"phone":      "+6591234567",
		"nric":       "S1234567D",
		"productId":  "PROD-456",
		"customerId": "CUST-789",
		"amount":     "150.50",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.SanitizeFields(fields)
	}
}

func BenchmarkSanitizeBatch(b *testing.B) {
	s := NewDefault()
	records := []map[string]any{
		{"email": "user1@example.com", "orderId": "ORD-1", "fullName": "User One"},
		{"email": "user2@example.com", "orderId": "ORD-2", "fullName": "User Two"},
		{"email": "user3@example.com", "orderId": "ORD-3", "fullName": "User Three"},
		{"email": "user4@example.com", "orderId": "ORD-4", "fullName": "User Four"},
		{"email": "user5@example.com", "orderId": "ORD-5", "fullName": "User Five"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.SanitizeBatch(records)
	}
}

func BenchmarkSanitizeFieldsVsIndividual(b *testing.B) {
	s := NewDefault()
	fields := map[string]string{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
		"phone":    "+6591234567",
	}

	b.Run("SanitizeFields", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(fields)
		}
	})

	b.Run("Individual", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			result := make(map[string]string, len(fields))
			for k, v := range fields {
				result[k] = s.SanitizeField(k, v)
			}
		}
	})
}
