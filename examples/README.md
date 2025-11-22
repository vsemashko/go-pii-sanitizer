# PII Sanitizer Examples

This directory contains example applications demonstrating how to use the PII sanitizer with different logging libraries and features.

## Available Examples

- **slog**: Standard library structured logging (Go 1.21+)
- **zap**: Uber's high-performance structured logger
- **zerolog**: Fast, low-allocation JSON logger
- **metrics**: Observability and metrics collection (v1.1.0+) 🆕

## Running Examples

### slog Example

```bash
cd examples/slog
go run main.go
```

**Features demonstrated:**
- Basic sanitization with `SlogValue()`
- Individual field sanitization with `SlogString()`
- Grouped fields with `SlogGroup()`
- Nested data structures
- Regional PII patterns (SG, MY, AE, TH, HK)
- Custom configurations for logs vs UI
- Partial masking strategy

### zap Example

```bash
cd examples/zap
go run main.go
```

**Features demonstrated:**
- Object marshaling with `ZapObject()`
- Field sanitization with `ZapField()`
- String sanitization with `ZapString()`
- Multiple objects in single log entry
- Slices and arrays
- Custom configurations
- Partial masking
- Hash strategy

### zerolog Example

```bash
cd examples/zerolog
go run main.go
```

**Features demonstrated:**
- Object marshaling with `ZerologObject()`
- String sanitization with `ZerologString()`
- Multiple objects
- Regional patterns
- Custom configurations
- Partial masking
- Hash strategy
- Pretty console output

## Common Patterns

### 1. Basic Usage

All three loggers follow a similar pattern:

```go
// Create sanitizer
s := sanitizer.NewDefault()

// Use with your logger
logger.Info("message", s.SlogValue(data))      // slog
logger.Info("message", zap.Object("key", s.ZapObject(data)))  // zap
logger.Info().Object("key", s.ZerologObject(data)).Msg("message")  // zerolog
```

### 2. Custom Configuration for Logs

Permissive configuration with broader patterns:

```go
logSanitizer := sanitizer.New(
    sanitizer.NewDefaultConfig().
        WithRedact("description", "memo", "reference").
        WithPreserve("orderId", "productId"),
)
```

### 3. Custom Configuration for UI

Strict configuration with explicit field lists:

```go
uiSanitizer := sanitizer.New(
    sanitizer.NewDefaultConfig().
        WithRedact(
            "fullName", "firstName", "lastName",
            "email", "emailAddress",
            "accountNumber", "bankAccount",
        ).
        WithPreserve(
            "orderId", "transactionId", "currency",
        ),
)
```

### 4. Partial Masking

Show last N characters:

```go
partialSanitizer := sanitizer.New(
    sanitizer.NewDefaultConfig().
        WithStrategy(sanitizer.StrategyPartial).
        WithPartialMasking('*', 0, 4),  // Show last 4 chars
)

// "john.doe@example.com" → "*************.com"
```

### 5. Hash Strategy

Generate consistent hashes:

```go
hashSanitizer := sanitizer.New(
    sanitizer.NewDefaultConfig().
        WithStrategy(sanitizer.StrategyHash),
)

// "user@example.com" → "sha256:a3c7e8f9..."
```

## Output Examples

### slog Output

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "msg": "Processing user",
  "user": {
    "fullName": "[REDACTED]",
    "email": "[REDACTED]",
    "phone": "[REDACTED]",
    "nric": "[REDACTED]",
    "orderId": "ORD-123456",
    "amount": 150.5
  }
}
```

### zap Output

```json
{
  "level": "info",
  "timestamp": "2024-01-15T10:30:00Z",
  "msg": "Processing user",
  "user": {
    "fullName": "[REDACTED]",
    "email": "[REDACTED]",
    "phone": "[REDACTED]",
    "nric": "[REDACTED]",
    "orderId": "ORD-123456",
    "amount": 150.5
  }
}
```

### zerolog Output

```json
{
  "level": "info",
  "time": 1705315800,
  "message": "Processing user",
  "user": {
    "fullName": "[REDACTED]",
    "email": "[REDACTED]",
    "phone": "[REDACTED]",
    "nric": "[REDACTED]",
    "orderId": "ORD-123456",
    "amount": 150.5
  }
}
```

## Regional PII Patterns

All examples demonstrate detection of regional PII:

- 🇸🇬 **Singapore**: NRIC (S1234567A), Phone (+6591234567)
- 🇲🇾 **Malaysia**: MyKad (901230-14-5678), Phone (+60123456789)
- 🇦🇪 **UAE**: Emirates ID (784-2020-1234567-1), IBAN
- 🇹🇭 **Thailand**: National ID (1-2345-67890-12-3), Phone (+66812345678)
- 🇭🇰 **Hong Kong**: HKID (A123456(7)), Phone (+85291234567)

## Performance Notes

- **slog**: Zero-allocation for structured logging (stdlib)
- **zap**: High-performance, suitable for high-volume logging
- **zerolog**: Extremely fast, minimal allocations

All integrations are designed for production use at <100 requests/min with minimal overhead.

## Next Steps

1. Choose the logger that fits your needs
2. Copy the relevant example code
3. Customize the configuration for your use case
4. Review the main README.md for detailed API documentation
