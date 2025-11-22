# Batch Processing Examples (v1.2.0+)

This directory contains examples demonstrating the batch processing capabilities introduced in v1.2.0 of the PII sanitizer.

## Overview

Batch processing allows you to efficiently sanitize multiple fields or records in a single operation, reducing overhead and improving performance for high-volume scenarios.

## Running the Example

```bash
cd examples/batch
go run main.go
```

## Features Demonstrated

### 1. **Batch Field Sanitization** (`SanitizeFields`)

Process multiple form fields or key-value pairs at once:

```go
s := sanitizer.NewDefault()

formData := map[string]string{
    "firstName": "John",
    "email":     "john@example.com",
    "phone":     "+6591234567",
    "orderId":   "ORD-123",
}

sanitized := s.SanitizeFields(formData)
```

**Use cases:**
- Form data processing
- API request/response sanitization
- Log entry sanitization
- Configuration validation

---

### 2. **Batch Record Processing** (`SanitizeBatch`)

Process multiple records (e.g., from database queries) efficiently:

```go
s := sanitizer.NewDefault()

users := []map[string]any{
    {"email": "alice@example.com", "orderId": "ORD-001"},
    {"email": "bob@example.com", "orderId": "ORD-002"},
}

sanitized := s.SanitizeBatch(users)
```

**Use cases:**
- Database query result sanitization
- Bulk data export
- Batch API responses
- Report generation

---

### 3. **Struct Tag Batch Processing** (`SanitizeBatchStructs`)

Process multiple typed structs with PII tag annotations:

```go
type Order struct {
    OrderID      string `pii:"preserve"`
    CustomerName string `pii:"redact"`
    Email        string `pii:"redact"`
}

orders := []Order{...}
sanitized := s.SanitizeBatchStructs(orders)
```

**Use cases:**
- Typed data processing
- ORM result sanitization
- Type-safe API responses
- Domain model export

---

### 4. **High-Volume Processing with Metrics**

Monitor performance for large batches:

```go
metrics := &MyMetrics{}
s := sanitizer.New(
    sanitizer.NewDefaultConfig().WithMetrics(metrics),
)

records := make([]map[string]any, 1000)
// ... populate records ...

sanitized := s.SanitizeBatch(records)
// Metrics are automatically collected
```

**Use cases:**
- Performance monitoring
- SLA tracking
- Throughput analysis
- Bottleneck identification

---

## Performance Characteristics

Batch processing provides consistent performance across different scales:

| Operation | Records | Throughput | Avg Latency |
|-----------|---------|------------|-------------|
| `SanitizeFields` | 10 fields | ~122K ops/sec | 8.2µs |
| `SanitizeBatch` | 5 records | ~30K batches/sec | 33µs |
| `SanitizeBatchStructs` | 3 structs | ~25K batches/sec | 40µs |
| High-volume | 1000 records | 145 batches/sec | 6.9ms |

*Benchmarks run on Intel Xeon @ 2.60GHz*

---

## Best Practices

### 1. **Choose the Right Method**

- **Single field**: Use `SanitizeField`
- **Multiple fields, same record**: Use `SanitizeFields`
- **Multiple records**: Use `SanitizeBatch`
- **Typed structs with tags**: Use `SanitizeBatchStructs`

### 2. **Enable Metrics for Monitoring**

```go
type MetricsCollector struct {
    processedFields int
    redactedFields  int
}

func (m *MetricsCollector) RecordSanitization(ctx sanitizer.MetricsContext) {
    m.processedFields++
    if ctx.Redacted {
        m.redactedFields++
    }
}
```

### 3. **Use Input Validation for Safety**

For large batches, enable safety limits:

```go
config := sanitizer.NewDefaultConfig().
    WithMaxFieldLength(10000).      // 10KB per field
    WithMaxContentLength(100000)    // 100KB content scan
```

### 4. **Leverage Struct Tags for Type Safety**

```go
type User struct {
    Email     string `pii:"redact" json:"email"`
    OrderID   string `pii:"preserve" json:"orderId"`
    InternalID string `pii:"-"`  // Exclude from output
}
```

---

## Common Patterns

### Pattern 1: Database Query Sanitization

```go
// Query users from database
rows, err := db.Query("SELECT id, email, name FROM users LIMIT 100")
// ... handle err ...

var users []map[string]any
// ... scan rows into users ...

// Sanitize all users in one operation
sanitized := sanitizer.NewDefault().SanitizeBatch(users)
```

### Pattern 2: API Response Sanitization

```go
// Sanitize API response before sending
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
    users := h.userService.GetAll()

    // Sanitize with struct tags
    sanitized := h.sanitizer.SanitizeBatchStructs(users)

    json.NewEncoder(w).Encode(sanitized)
}
```

### Pattern 3: Bulk Export with Progress

```go
func ExportUsers(ctx context.Context, writer io.Writer) error {
    const batchSize = 1000
    offset := 0

    for {
        users := fetchUsers(offset, batchSize)
        if len(users) == 0 {
            break
        }

        sanitized := sanitizer.NewDefault().SanitizeBatch(users)

        // Write sanitized data
        if err := writeJSON(writer, sanitized); err != nil {
            return err
        }

        offset += batchSize
    }

    return nil
}
```

---

## Troubleshooting

### Issue: Slow batch processing

**Solutions:**
1. Enable `MaxContentLength` to limit regex scanning
2. Reduce enabled regions if only specific patterns needed
3. Use struct tags to avoid pattern matching overhead
4. Process in smaller batches (100-1000 records)

### Issue: High memory usage

**Solutions:**
1. Process records in smaller batches
2. Stream results instead of holding all in memory
3. Enable `MaxFieldLength` to truncate oversized values

### Issue: Inconsistent sanitization

**Solutions:**
1. Check struct tag priorities: `preserve > redact > pattern matching`
2. Verify AlwaysRedact/NeverRedact lists
3. Review regional pattern configuration

---

## Integration Examples

### With Logging

```go
sanitized := s.SanitizeBatch(records)
logger.Info("Processed batch",
    zap.Int("count", len(sanitized)),
    zap.Any("sample", sanitized[0]))
```

### With gRPC

```go
func (s *Server) ListUsers(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
    users := s.store.GetUsers()
    sanitized := s.sanitizer.SanitizeBatchStructs(users)

    return &pb.ListResponse{Users: sanitized}, nil
}
```

### With GraphQL

```go
func (r *queryResolver) Users(ctx context.Context) ([]*model.User, error) {
    users := r.userService.GetAll()
    sanitized := r.sanitizer.SanitizeBatchStructs(users)

    return sanitized, nil
}
```

---

## Next Steps

1. Review the [metrics example](../metrics/) for observability integration
2. Check the [main README](../../README.md) for API documentation
3. Explore struct tag features for type-safe sanitization
4. Run benchmarks to measure performance in your environment
