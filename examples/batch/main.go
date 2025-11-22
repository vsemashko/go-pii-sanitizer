package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

func main() {
	fmt.Println("Go PII Sanitizer - Batch Processing Examples (v1.2.0)")
	fmt.Println(strings.Repeat("=", 80))

	// Example 1: Batch field sanitization
	fmt.Println("\n### Example 1: Batch Field Sanitization ###")
	runBatchFieldsExample()

	// Example 2: Batch record processing
	fmt.Println("\n\n### Example 2: Batch Record Processing ###")
	runBatchRecordsExample()

	// Example 3: Struct tag batch processing
	fmt.Println("\n\n### Example 3: Struct Tag Batch Processing ###")
	runStructTagsBatchExample()

	// Example 4: High-volume processing with metrics
	fmt.Println("\n\n### Example 4: High-Volume Processing with Metrics ###")
	runHighVolumeExample()
}

func runBatchFieldsExample() {
	s := sanitizer.NewDefault()

	// Sanitize multiple form fields at once
	formData := map[string]string{
		"firstName":    "John",
		"lastName":     "Doe",
		"email":        "john.doe@example.com",
		"phone":        "+6591234567",
		"orderId":      "ORD-2025-001",
		"productId":    "PROD-XYZ-789",
		"shippingAddr": "123 Main Street, Singapore",
	}

	fmt.Println("Original form data:")
	printMap(formData)

	sanitized := s.SanitizeFields(formData)

	fmt.Println("\nSanitized form data:")
	printMap(sanitized)
}

func runBatchRecordsExample() {
	s := sanitizer.NewDefault()

	// Process multiple user records (e.g., from a database query)
	users := []map[string]any{
		{
			"id":       1,
			"email":    "alice@example.com",
			"fullName": "Alice Smith",
			"orderId":  "ORD-001",
			"amount":   150.50,
		},
		{
			"id":       2,
			"email":    "bob@example.com",
			"fullName": "Bob Jones",
			"orderId":  "ORD-002",
			"amount":   275.00,
		},
		{
			"id":       3,
			"email":    "charlie@example.com",
			"fullName": "Charlie Brown",
			"orderId":  "ORD-003",
			"amount":   99.99,
		},
	}

	fmt.Println("Processing", len(users), "user records...")

	sanitized := s.SanitizeBatch(users)

	fmt.Println("\nSanitized records:")
	for i, record := range sanitized {
		fmt.Printf("\nUser %d:\n", i+1)
		prettyPrint(record)
	}
}

func runStructTagsBatchExample() {
	// Define a struct with PII tags
	type Order struct {
		OrderID      string  `json:"orderId" pii:"preserve"`
		CustomerName string  `json:"customerName" pii:"redact"`
		Email        string  `json:"email" pii:"redact"`
		Amount       float64 `json:"amount" pii:"preserve"`
		Notes        string  `json:"notes" pii:"redact"`
		Status       string  `json:"status" pii:"preserve"`
	}

	s := sanitizer.NewDefault()

	// Batch process multiple orders
	orders := []Order{
		{
			OrderID:      "ORD-2025-001",
			CustomerName: "Alice Smith",
			Email:        "alice@example.com",
			Amount:       150.50,
			Notes:        "Special delivery instructions",
			Status:       "shipped",
		},
		{
			OrderID:      "ORD-2025-002",
			CustomerName: "Bob Jones",
			Email:        "bob@example.com",
			Amount:       275.00,
			Notes:        "Gift wrap requested",
			Status:       "processing",
		},
	}

	fmt.Println("Processing", len(orders), "orders with struct tags...")

	sanitized := s.SanitizeBatchStructs(orders)

	fmt.Println("\nSanitized orders:")
	for i, order := range sanitized {
		fmt.Printf("\nOrder %d:\n", i+1)
		prettyPrint(order)
	}
}

func runHighVolumeExample() {
	// Custom metrics collector for tracking
	metrics := &metricsCollector{}

	// Create sanitizer with metrics
	s := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithMetrics(metrics),
	)

	// Simulate processing 1000 records
	const recordCount = 1000
	records := make([]map[string]any, recordCount)

	for i := 0; i < recordCount; i++ {
		records[i] = map[string]any{
			"id":       i + 1,
			"email":    fmt.Sprintf("user%d@example.com", i),
			"fullName": fmt.Sprintf("User %d", i),
			"orderId":  fmt.Sprintf("ORD-%05d", i),
			"amount":   float64(i) * 10.5,
		}
	}

	fmt.Printf("Processing %d records...\n", recordCount)
	start := time.Now()

	sanitized := s.SanitizeBatch(records)

	duration := time.Since(start)

	fmt.Printf("\n✅ Batch processing complete!\n")
	fmt.Printf("   Records processed: %d\n", len(sanitized))
	fmt.Printf("   Total duration:    %v\n", duration)
	fmt.Printf("   Avg per record:    %v\n", duration/time.Duration(recordCount))
	fmt.Printf("   Throughput:        %.0f records/sec\n\n",
		float64(recordCount)/duration.Seconds())

	// Show a sample of results
	fmt.Println("Sample sanitized record:")
	prettyPrint(sanitized[0])
}

// Helper: Custom metrics collector for batch example
type metricsCollector struct {
	totalFields    int
	redactedFields int
	totalDuration  time.Duration
}

func (m *metricsCollector) RecordSanitization(ctx sanitizer.MetricsContext) {
	m.totalFields++
	if ctx.Redacted {
		m.redactedFields++
	}
	m.totalDuration += ctx.Duration
}

// Helper functions
func printMap(m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	for _, k := range keys {
		fmt.Printf("  %-15s : %s\n", k, m[k])
	}
}

func prettyPrint(v any) {
	data, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		log.Printf("Error marshaling: %v", err)
		return
	}
	fmt.Println(string(data))
}
