package sanitizer

import "time"

// MetricsCollector is an optional interface for collecting sanitizer metrics.
// Implementations can track sanitization operations, performance, and false positives.
//
// This interface allows integration with monitoring systems like Prometheus, StatsD,
// or custom telemetry systems.
//
// Example implementation:
//
//	type PrometheusMetrics struct {
//	    sanitizations *prometheus.CounterVec
//	    duration      *prometheus.HistogramVec
//	}
//
//	func (p *PrometheusMetrics) RecordSanitization(ctx MetricsContext) {
//	    p.sanitizations.WithLabelValues(ctx.PIIType, ctx.FieldName).Inc()
//	    p.duration.WithLabelValues(ctx.PIIType).Observe(ctx.Duration.Seconds())
//	}
//
// Usage:
//
//	config := sanitizer.NewDefaultConfig().WithMetrics(myMetrics)
//	s := sanitizer.New(config)
type MetricsCollector interface {
	// RecordSanitization is called when a field is sanitized
	RecordSanitization(ctx MetricsContext)
}

// MetricsContext provides context about a sanitization operation
type MetricsContext struct {
	// FieldName is the name of the field being sanitized
	FieldName string

	// PIIType is the type of PII detected (e.g., "email", "nric", "credit_card")
	// Empty if no PII was detected
	PIIType string

	// Redacted indicates whether the value was actually redacted
	Redacted bool

	// Strategy is the redaction strategy used
	Strategy RedactionStrategy

	// Duration is how long the sanitization took
	Duration time.Duration

	// ValueLength is the original value length (for performance tracking)
	ValueLength int
}

// NoOpMetrics is a no-op implementation of MetricsCollector
// Used as default when no metrics collector is configured
type NoOpMetrics struct{}

// RecordSanitization does nothing (no-op implementation)
func (NoOpMetrics) RecordSanitization(MetricsContext) {}
