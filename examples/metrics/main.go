package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

// Example 1: Simple logging metrics collector
type LoggingMetrics struct {
	mu sync.Mutex
}

func (m *LoggingMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := "preserved"
	if ctx.Redacted {
		status = "redacted"
	}

	log.Printf("[METRICS] Field: %-20s | Type: %-15s | Status: %-10s | Duration: %6d µs | Length: %6d bytes",
		ctx.FieldName,
		ctx.PIIType,
		status,
		ctx.Duration.Microseconds(),
		ctx.ValueLength,
	)
}

// Example 2: Aggregating metrics collector (production-ready)
type AggregatingMetrics struct {
	mu    sync.Mutex
	stats map[string]*FieldStats
}

type FieldStats struct {
	TotalCalls     int64
	RedactedCalls  int64
	TotalDuration  time.Duration
	MinDuration    time.Duration
	MaxDuration    time.Duration
	PIITypeCounter map[string]int64
}

func NewAggregatingMetrics() *AggregatingMetrics {
	return &AggregatingMetrics{
		stats: make(map[string]*FieldStats),
	}
}

func (m *AggregatingMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, exists := m.stats[ctx.FieldName]
	if !exists {
		stats = &FieldStats{
			MinDuration:    ctx.Duration,
			MaxDuration:    ctx.Duration,
			PIITypeCounter: make(map[string]int64),
		}
		m.stats[ctx.FieldName] = stats
	}

	stats.TotalCalls++
	if ctx.Redacted {
		stats.RedactedCalls++
	}
	stats.TotalDuration += ctx.Duration

	if ctx.Duration < stats.MinDuration {
		stats.MinDuration = ctx.Duration
	}
	if ctx.Duration > stats.MaxDuration {
		stats.MaxDuration = ctx.Duration
	}

	if ctx.PIIType != "" {
		stats.PIITypeCounter[ctx.PIIType]++
	}
}

func (m *AggregatingMetrics) PrintReport() {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("METRICS REPORT")
	fmt.Println(strings.Repeat("=", 80))

	for fieldName, stats := range m.stats {
		avgDuration := stats.TotalDuration / time.Duration(stats.TotalCalls)
		redactionRate := float64(stats.RedactedCalls) / float64(stats.TotalCalls) * 100

		fmt.Printf("\nField: %s\n", fieldName)
		fmt.Printf("  Total Calls:     %d\n", stats.TotalCalls)
		fmt.Printf("  Redacted:        %d (%.1f%%)\n", stats.RedactedCalls, redactionRate)
		fmt.Printf("  Avg Duration:    %v\n", avgDuration)
		fmt.Printf("  Min Duration:    %v\n", stats.MinDuration)
		fmt.Printf("  Max Duration:    %v\n", stats.MaxDuration)

		if len(stats.PIITypeCounter) > 0 {
			fmt.Println("  PII Types Detected:")
			for piiType, count := range stats.PIITypeCounter {
				fmt.Printf("    - %s: %d\n", piiType, count)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

// Example 3: Prometheus-style metrics (mock implementation)
type PrometheusMetrics struct {
	mu                 sync.Mutex
	sanitizationCount  map[string]map[string]int64 // [piiType][fieldName] -> count
	sanitizationErrors int64
	durationHistogram  map[string][]time.Duration // [piiType] -> durations
}

func NewPrometheusMetrics() *PrometheusMetrics {
	return &PrometheusMetrics{
		sanitizationCount: make(map[string]map[string]int64),
		durationHistogram: make(map[string][]time.Duration),
	}
}

func (m *PrometheusMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
	m.mu.Lock()
	defer m.mu.Unlock()

	piiType := ctx.PIIType
	if piiType == "" {
		piiType = "none"
	}

	// Increment counter
	if m.sanitizationCount[piiType] == nil {
		m.sanitizationCount[piiType] = make(map[string]int64)
	}
	m.sanitizationCount[piiType][ctx.FieldName]++

	// Record duration histogram
	m.durationHistogram[piiType] = append(m.durationHistogram[piiType], ctx.Duration)
}

func (m *PrometheusMetrics) ExportMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println("\n# HELP pii_sanitizer_operations_total Total number of sanitization operations")
	fmt.Println("# TYPE pii_sanitizer_operations_total counter")

	for piiType, fields := range m.sanitizationCount {
		for fieldName, count := range fields {
			fmt.Printf("pii_sanitizer_operations_total{pii_type=\"%s\",field_name=\"%s\"} %d\n",
				piiType, fieldName, count)
		}
	}

	fmt.Println("\n# HELP pii_sanitizer_duration_seconds Histogram of sanitization operation durations")
	fmt.Println("# TYPE pii_sanitizer_duration_seconds histogram")

	for piiType, durations := range m.durationHistogram {
		if len(durations) == 0 {
			continue
		}

		// Calculate percentiles
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avg := total / time.Duration(len(durations))

		fmt.Printf("pii_sanitizer_duration_seconds{pii_type=\"%s\",quantile=\"0.5\"} %.6f\n",
			piiType, avg.Seconds())
	}
}

func main() {
	fmt.Println("Go PII Sanitizer - Metrics Examples (v1.1.0)")
	fmt.Println(strings.Repeat("=", 80))

	// Example 1: Simple logging metrics
	fmt.Println("\n### Example 1: Simple Logging Metrics ###")
	runLoggingExample()

	// Example 2: Aggregating metrics with report
	fmt.Println("\n\n### Example 2: Aggregating Metrics ###")
	runAggregatingExample()

	// Example 3: Prometheus-style metrics
	fmt.Println("\n\n### Example 3: Prometheus-Style Metrics ###")
	runPrometheusExample()

	// Example 4: Production scenario with safety features
	fmt.Println("\n\n### Example 4: Production with Safety Features ###")
	runProductionExample()
}

func runLoggingExample() {
	metrics := &LoggingMetrics{}
	config := sanitizer.NewDefaultConfig().WithMetrics(metrics)
	s := sanitizer.New(config)

	// Simulate sanitization operations
	testData := map[string]string{
		"email":       "user@example.com",
		"orderId":     "ORD-12345",
		"fullName":    "John Doe",
		"accountNumber": "1234567890",
		"productId":   "PROD-789",
	}

	for field, value := range testData {
		s.SanitizeField(field, value)
	}
}

func runAggregatingExample() {
	metrics := NewAggregatingMetrics()
	config := sanitizer.NewDefaultConfig().WithMetrics(metrics)
	s := sanitizer.New(config)

	// Simulate multiple sanitization operations
	for i := 0; i < 100; i++ {
		s.SanitizeField("email", "user@example.com")
		s.SanitizeField("orderId", fmt.Sprintf("ORD-%d", i))
		s.SanitizeField("fullName", "John Doe")

		if i%10 == 0 {
			s.SanitizeField("nric", "S1234567D") // Singapore NRIC
		}
	}

	// Print aggregated report
	metrics.PrintReport()
}

func runPrometheusExample() {
	metrics := NewPrometheusMetrics()
	config := sanitizer.NewDefaultConfig().WithMetrics(metrics)
	s := sanitizer.New(config)

	// Simulate operations
	for i := 0; i < 50; i++ {
		s.SanitizeField("email", "user@example.com")
		s.SanitizeField("orderId", "ORD-123")
	}

	// Export Prometheus-style metrics
	metrics.ExportMetrics()
}

func runProductionExample() {
	metrics := NewAggregatingMetrics()

	// Production config with all v1.1.0 features
	config := sanitizer.NewDefaultConfig().
		WithMetrics(metrics).                 // Enable metrics
		WithMaxFieldLength(10000).            // Limit field size (10KB)
		WithMaxContentLength(100000).         // Limit content scan (100KB)
		WithRegions(sanitizer.Singapore).     // Singapore only
		WithRedact("internalNotes").          // Custom PII fields
		WithPreserve("orderId", "productId")  // Safe fields

	s := sanitizer.New(config)

	fmt.Println("Sanitizing production data with safety limits...")

	// Simulate production workload
	productionData := []struct {
		field string
		value string
	}{
		{"email", "customer@example.com"},
		{"orderId", "ORD-2025-001"},
		{"fullName", "Jane Smith"},
		{"nric", "S1234567D"},
		{"productId", "PROD-XYZ-789"},
		{"internalNotes", "Customer requested expedited shipping"},
		{"accountNumber", "9876543210"},
	}

	for _, data := range productionData {
		result := s.SanitizeField(data.field, data.value)
		fmt.Printf("  %-20s: %s\n", data.field, result)
	}

	// Print metrics report
	metrics.PrintReport()

	fmt.Println("\n✅ Production example complete with metrics tracking!")
}
