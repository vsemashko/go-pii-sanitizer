# Metrics Example (v1.1.0+)

This example demonstrates how to use the metrics interface added in v1.1.0 to track sanitization operations in production.

## What's Demonstrated

1. **Simple Logging Metrics** - Basic metrics logging to stdout
2. **Aggregating Metrics** - Production-ready metrics aggregation with statistics
3. **Prometheus-Style Metrics** - Export metrics in Prometheus format
4. **Production Configuration** - Complete example with all v1.1.0 safety features

## Running the Example

```bash
cd examples/metrics
go run main.go
```

## Output

The example will show:
- Real-time logging of sanitization operations
- Aggregated statistics (call counts, redaction rates, performance)
- Prometheus-compatible metric exports
- Production scenario with safety limits

## Metrics Tracked

Each sanitization operation records:
- `FieldName`: Name of the field being sanitized
- `PIIType`: Type of PII detected (email, nric, etc.)
- `Redacted`: Whether the value was redacted
- `Strategy`: Redaction strategy used
- `Duration`: Time taken to sanitize
- `ValueLength`: Original value length

## Integration Examples

### 1. Simple Logging (Development)

```go
type LoggingMetrics struct {}

func (m *LoggingMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
    log.Printf("Sanitized %s: %s (redacted: %v, duration: %v)",
        ctx.FieldName, ctx.PIIType, ctx.Redacted, ctx.Duration)
}

config := sanitizer.NewDefaultConfig().WithMetrics(&LoggingMetrics{})
```

### 2. Prometheus Integration (Production)

```go
import "github.com/prometheus/client_golang/prometheus"

type PrometheusMetrics struct {
    sanitizationCounter *prometheus.CounterVec
    durationHistogram   *prometheus.HistogramVec
}

func (m *PrometheusMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
    m.sanitizationCounter.WithLabelValues(ctx.PIIType, ctx.FieldName).Inc()
    m.durationHistogram.WithLabelValues(ctx.PIIType).Observe(ctx.Duration.Seconds())
}
```

### 3. StatsD Integration

```go
import "github.com/cactus/go-statsd-client/statsd"

type StatsDMetrics struct {
    client statsd.Statter
}

func (m *StatsDMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
    m.client.Inc("pii.sanitizations", 1, 1.0)
    m.client.Timing("pii.duration", ctx.Duration.Milliseconds(), 1.0)

    if ctx.Redacted {
        m.client.Inc(fmt.Sprintf("pii.redacted.%s", ctx.PIIType), 1, 1.0)
    }
}
```

### 4. Custom Application Metrics

```go
type AppMetrics struct {
    db *sql.DB
}

func (m *AppMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
    // Store metrics in database for analytics
    m.db.Exec(`
        INSERT INTO sanitization_metrics
        (field_name, pii_type, redacted, duration_us, timestamp)
        VALUES (?, ?, ?, ?, ?)`,
        ctx.FieldName, ctx.PIIType, ctx.Redacted,
        ctx.Duration.Microseconds(), time.Now())
}
```

## Production Configuration

```go
metrics := NewAggregatingMetrics()

config := sanitizer.NewDefaultConfig().
    WithMetrics(metrics).                 // Enable observability
    WithMaxFieldLength(10000).            // Limit field size (10KB)
    WithMaxContentLength(100000).         // Prevent regex DOS (100KB)
    WithRegions(sanitizer.Singapore).     // Region-specific
    WithRedact("internalNotes").          // Custom PII
    WithPreserve("orderId", "productId")  // Safe fields

s := sanitizer.New(config)
```

## Use Cases

### 1. Performance Monitoring
Track sanitization performance in production to identify bottlenecks.

### 2. False Positive Detection
Monitor which fields are being redacted to identify potential false positives.

### 3. Compliance Auditing
Record all PII detections for compliance and audit trails.

### 4. Capacity Planning
Understand sanitization volume and resource requirements.

### 5. A/B Testing
Compare different sanitization strategies and configurations.

## Best Practices

1. **Enable in Production** - Metrics are zero-cost when disabled, but invaluable in production
2. **Aggregate Before Export** - Use aggregating collectors to reduce metric volume
3. **Monitor Performance** - Alert on p99 duration spikes
4. **Track Redaction Rates** - Unusual rates may indicate false positives/negatives
5. **Use Sampling** - For extremely high-volume systems, sample metrics (e.g., 1%)

## Performance Impact

Metrics collection adds minimal overhead:
- **Without metrics**: 841 ns/op
- **With metrics**: ~1,253 ns/op (+49%, still >800K ops/sec)

The overhead comes from:
- `time.Now()` call at start
- `time.Since()` call at end
- Interface method call

This is negligible compared to the value provided by production observability.

## Troubleshooting

### High Redaction Rates
If you see unexpectedly high redaction rates (>50%):
- Check for overly broad field name patterns
- Review custom redact lists
- Verify you're using `WithPreserve` for safe fields

### Performance Issues
If sanitization is slower than expected:
- Check metrics for which PII types are slow
- Consider using `WithMaxContentLength` to limit regex scans
- Review regional patterns (disable unused regions)

### Missing Metrics
If metrics aren't being recorded:
- Verify metrics collector is not nil
- Check that `RecordSanitization` is being called
- Ensure no panics in metric recording code

## Additional Resources

- [IMPROVEMENTS_V1.1.md](../../IMPROVEMENTS_V1.1.md) - v1.1.0 features
- [PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance guide
- [Prometheus Integration](https://prometheus.io/docs/guides/go-application/)
- [StatsD Protocol](https://github.com/statsd/statsd/blob/master/docs/metric_types.md)
