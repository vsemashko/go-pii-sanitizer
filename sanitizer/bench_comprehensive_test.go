package sanitizer

import (
	"testing"
)

// Comprehensive benchmark suite for v1.2.0

// Benchmark large batch operations
func BenchmarkSanitizeBatchLarge(b *testing.B) {
	s := NewDefault()

	// Create 1000 records
	records := make([]map[string]any, 1000)
	for i := 0; i < 1000; i++ {
		records[i] = map[string]any{
			"email":    "user" + string(rune(i)) + "@example.com",
			"fullName": "User Name",
			"orderId":  "ORD-" + string(rune(i)),
			"amount":   150.50,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.SanitizeBatch(records)
	}
}

// Benchmark with metrics enabled vs disabled
func BenchmarkWithMetrics(b *testing.B) {
	fields := map[string]string{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
	}

	b.Run("WithoutMetrics", func(b *testing.B) {
		s := NewDefault()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(fields)
		}
	})

	b.Run("WithMetrics", func(b *testing.B) {
		metrics := &testMetrics{calls: make([]MetricsContext, 0, 1000)}
		s := New(NewDefaultConfig().WithMetrics(metrics))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(fields)
		}
	})
}

// Benchmark different redaction strategies
func BenchmarkStrategies(b *testing.B) {
	data := map[string]string{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"phone":    "+6591234567",
	}

	b.Run("Full", func(b *testing.B) {
		s := New(NewDefaultConfig().WithStrategy(StrategyFull))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})

	b.Run("Partial", func(b *testing.B) {
		s := New(NewDefaultConfig().
			WithStrategy(StrategyPartial).
			WithPartialMasking('*', 0, 4))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})

	b.Run("Hash", func(b *testing.B) {
		s := New(NewDefaultConfig().WithStrategy(StrategyHash))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})
}

// Benchmark struct tag processing
func BenchmarkStructTagsVsMap(b *testing.B) {
	type User struct {
		Email    string `pii:"redact" json:"email"`
		FullName string `pii:"redact" json:"fullName"`
		OrderID  string `pii:"preserve" json:"orderId"`
	}

	user := User{
		Email:    "user@example.com",
		FullName: "John Doe",
		OrderID:  "ORD-123",
	}

	userMap := map[string]any{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
	}

	s := NewDefault()

	b.Run("StructWithTags", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeStructWithTags(user)
		}
	})

	b.Run("Map", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeMap(userMap)
		}
	})
}

// Benchmark regional patterns
func BenchmarkRegionalPatterns(b *testing.B) {
	testData := map[string]string{
		"nric":      "S1234567D",
		"phone":     "+6591234567",
		"orderId":   "ORD-123",
		"email":     "user@example.com",
	}

	b.Run("AllRegions", func(b *testing.B) {
		s := NewDefault() // All regions enabled
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(testData)
		}
	})

	b.Run("SingleRegion", func(b *testing.B) {
		s := NewForRegion(Singapore) // Only Singapore
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(testData)
		}
	})
}

// Benchmark nested structures
func BenchmarkNestedStructures(b *testing.B) {
	s := NewDefault()

	shallowData := map[string]any{
		"email":  "user@example.com",
		"orderId": "ORD-123",
	}

	deepData := map[string]any{
		"user": map[string]any{
			"profile": map[string]any{
				"email":    "user@example.com",
				"fullName": "John Doe",
			},
			"orders": []any{
				map[string]any{"orderId": "ORD-1", "amount": 100},
				map[string]any{"orderId": "ORD-2", "amount": 200},
			},
		},
	}

	b.Run("Shallow", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeMap(shallowData)
		}
	})

	b.Run("Deep", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeMap(deepData)
		}
	})
}

// Benchmark with input validation limits
func BenchmarkWithLimits(b *testing.B) {
	longValue := make([]byte, 100000) // 100KB
	for i := range longValue {
		longValue[i] = 'a'
	}
	longString := string(longValue)

	data := map[string]string{
		"description": longString,
		"email":       "user@example.com",
	}

	b.Run("NoLimits", func(b *testing.B) {
		s := NewDefault()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})

	b.Run("WithMaxFieldLength", func(b *testing.B) {
		s := New(NewDefaultConfig().WithMaxFieldLength(10000))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})

	b.Run("WithMaxContentLength", func(b *testing.B) {
		s := New(NewDefaultConfig().WithMaxContentLength(10000))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})
}

// Benchmark JSON sanitization
func BenchmarkJSON(b *testing.B) {
	s := NewDefault()

	jsonData := []byte(`{
		"email": "user@example.com",
		"fullName": "John Doe",
		"orderId": "ORD-123",
		"phone": "+6591234567",
		"amount": 150.50
	}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.SanitizeJSON(jsonData)
	}
}

// Benchmark explicit redact/preserve lists
func BenchmarkExplicitLists(b *testing.B) {
	data := map[string]string{
		"email":         "user@example.com",
		"customField1":  "secret",
		"customField2":  "public",
		"orderId":       "ORD-123",
	}

	b.Run("Default", func(b *testing.B) {
		s := NewDefault()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})

	b.Run("WithRedactList", func(b *testing.B) {
		s := New(NewDefaultConfig().
			WithRedact("customField1"))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})

	b.Run("WithPreserveList", func(b *testing.B) {
		s := New(NewDefaultConfig().
			WithPreserve("customField2"))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(data)
		}
	})
}

// Memory allocation benchmark
func BenchmarkAllocations(b *testing.B) {
	s := NewDefault()

	b.Run("SingleField", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeField("email", "user@example.com")
		}
	})

	b.Run("TenFields", func(b *testing.B) {
		fields := map[string]string{
			"email":      "user@example.com",
			"fullName":   "John Doe",
			"orderId":    "ORD-123",
			"phone":      "+6591234567",
			"address":    "123 Main St",
			"city":       "Singapore",
			"country":    "SG",
			"postalCode": "123456",
			"amount":     "150.50",
			"currency":   "SGD",
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			s.SanitizeFields(fields)
		}
	})
}

// Benchmark concurrent usage (sanitizer is thread-safe)
func BenchmarkConcurrent(b *testing.B) {
	s := NewDefault()
	fields := map[string]string{
		"email":    "user@example.com",
		"fullName": "John Doe",
		"orderId":  "ORD-123",
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.SanitizeFields(fields)
		}
	})
}
