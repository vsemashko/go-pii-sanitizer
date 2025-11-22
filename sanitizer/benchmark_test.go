package sanitizer

import (
	"testing"
)

// Benchmark tests for performance measurement

func BenchmarkSanitizeField_Simple(b *testing.B) {
	s := NewDefault()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("email", "user@example.com")
	}
}

func BenchmarkSanitizeField_NoMatch(b *testing.B) {
	s := NewDefault()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("orderId", "ORD-12345")
	}
}

func BenchmarkSanitizeField_ContentMatch(b *testing.B) {
	s := NewDefault()
	text := "Contact me at user@example.com for details"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("description", text)
	}
}

func BenchmarkSanitizeMap_Small(b *testing.B) {
	s := NewDefault()
	data := map[string]interface{}{
		"orderId": "ORD-123",
		"email":   "user@example.com",
		"amount":  100.50,
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeMap(data)
	}
}

func BenchmarkSanitizeMap_Nested(b *testing.B) {
	s := NewDefault()
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"fullName": "John Doe",
			"email":    "john@example.com",
			"phone":    "+6591234567",
		},
		"order": map[string]interface{}{
			"orderId": "ORD-123",
			"amount":  99.99,
		},
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeMap(data)
	}
}

func BenchmarkSanitizeMap_Deep(b *testing.B) {
	s := NewDefault()
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeMap(data)
	}
}

func BenchmarkSanitizeJSON(b *testing.B) {
	s := NewDefault()
	jsonData := []byte(`{"email":"user@example.com","orderId":"ORD-123","amount":100.50}`)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeJSON(jsonData)
	}
}

func BenchmarkSanitizeStruct(b *testing.B) {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeStruct(user)
	}
}

func BenchmarkPartialMasking(b *testing.B) {
	config := NewDefaultConfig().
		WithStrategy(StrategyPartial).
		WithPartialMasking('*', 0, 4)
	s := New(config)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("creditCard", "4532-1234-5678-9010")
	}
}

func BenchmarkHashStrategy(b *testing.B) {
	s := New(NewDefaultConfig().WithStrategy(StrategyHash))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("email", "user@example.com")
	}
}

// Benchmark region-specific patterns
func BenchmarkSingaporeNRIC(b *testing.B) {
	s := NewForRegion(Singapore)
	text := "My NRIC is S1234567A"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("text", text)
	}
}

func BenchmarkMalaysiaMyKad(b *testing.B) {
	s := NewForRegion(Malaysia)
	text := "IC: 901230-14-5678"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("text", text)
	}
}

func BenchmarkUAEIBAN(b *testing.B) {
	s := NewForRegion(UAE)
	text := "IBAN: AE07 0331 2345 6789 0123 456"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		s.SanitizeField("text", text)
	}
}
