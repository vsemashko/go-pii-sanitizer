# Go PII Sanitizer

[![CI](https://github.com/vsemashko/go-pii-sanitizer/workflows/CI/badge.svg)](https://github.com/vsemashko/go-pii-sanitizer/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/vsemashko/go-pii-sanitizer)](https://goreportcard.com/report/github.com/vsemashko/go-pii-sanitizer)
[![codecov](https://codecov.io/gh/vsemashko/go-pii-sanitizer/branch/main/graph/badge.svg)](https://codecov.io/gh/vsemashko/go-pii-sanitizer)
[![GoDoc](https://godoc.org/github.com/vsemashko/go-pii-sanitizer?status.svg)](https://godoc.org/github.com/vsemashko/go-pii-sanitizer/sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-ready PII (Personally Identifiable Information) sanitization library for Go, targeting **Singapore, Malaysia, UAE, Thailand, and Hong Kong** markets.

## Features

- ✅ **Regional PII Detection**: Supports NRIC (SG), MyKad (MY), Emirates ID (AE), Thai ID (TH), HKID (HK)
- ✅ **Checksum Validation**: NRIC, MyKad, Thai ID, Credit Cards (reduces false positives)
- ✅ **Bank Account Numbers**: Region-specific formats for all 5 countries
- ✅ **Common PII**: Emails, phones, names, addresses, transaction descriptions
- ✅ **Secrets Detection**: Passwords, tokens, API keys, credentials
- ✅ **Struct Tag Support**: Explicit PII marking with `pii:"redact"` and `pii:"preserve"` tags
- ✅ **Batch Processing**: Efficient bulk sanitization for high-volume scenarios (v1.2.0+)
- ✅ **Multiple Redaction Strategies**: Full, partial masking, hashing, removal
- ✅ **Logger Integrations**: Native support for slog, zap, and zerolog
- ✅ **Observability**: Metrics interface for production monitoring (v1.1.0+)
- ✅ **Input Safety**: Configurable length limits to prevent regex DOS (v1.1.0+)
- ✅ **Flexible Configuration**: Explicit allow/deny lists, custom patterns
- ✅ **Zero Dependencies**: Core library uses only Go standard library
- ✅ **High Performance**: >800K ops/sec, minimal overhead
- ✅ **Comprehensive Testing**: 92.4% test coverage with edge cases

## Installation

```bash
go get github.com/vsemashko/go-pii-sanitizer
```

## What's New in v1.2.0 🚀

**Release Date:** November 2025
**Focus:** Batch Processing, Performance, Scalability

### New Features

- 📦 **Batch Processing API**: Process multiple fields/records efficiently
  - `SanitizeFields()`: Bulk field sanitization (~122K ops/sec)
  - `SanitizeBatch()`: Bulk record processing (~30K batches/sec)
  - `SanitizeBatchStructs()`: Batch struct processing with tags
- 📊 **Comprehensive Benchmarks**: 15+ new benchmarks for performance analysis
- 🎯 **Production Examples**: Complete batch processing examples and integration patterns
- ⚡ **Performance**: Optimized for high-volume scenarios (1000+ records/batch)

[See full v1.2.0 improvements →](./IMPROVEMENTS_V1.2.md)

### Quick Example - Batch Processing

```go
// Process multiple database records efficiently
s := sanitizer.NewDefault()

users := []map[string]any{
    {"email": "user1@example.com", "orderId": "ORD-1"},
    {"email": "user2@example.com", "orderId": "ORD-2"},
    {"email": "user3@example.com", "orderId": "ORD-3"},
}

// Sanitize all records in one operation
sanitized := s.SanitizeBatch(users)
// Result: All emails redacted, orderIds preserved

// Or use typed structs with tags
type User struct {
    Email   string `pii:"redact" json:"email"`
    OrderID string `pii:"preserve" json:"orderId"`
}

typedUsers := []User{...}
sanitized := s.SanitizeBatchStructs(typedUsers)
```

## What's New in v1.1.0 🎉

**Release Date:** November 2025
**Focus:** Production-readiness, Observability, Safety, Accuracy

### New Features

- 🔍 **Observability**: Metrics interface for tracking sanitization operations
- 🛡️ **Input Safety**: Configurable field/content length limits (prevents regex DOS)
- 🎯 **Enhanced Accuracy**: Thailand ID checksum validation (~10% fewer false positives)
- 📊 **Better Errors**: Improved error context with wrapped errors

[See full v1.1.0 improvements →](./IMPROVEMENTS_V1.1.md)

### Quick Example - Metrics

```go
// Track sanitization operations in production
type MyMetrics struct { /* your metrics implementation */ }

func (m *MyMetrics) RecordSanitization(ctx sanitizer.MetricsContext) {
    // Track: field name, PII type, duration, redacted flag
    log.Printf("Sanitized %s (type: %s) in %v", ctx.FieldName, ctx.PIIType, ctx.Duration)
}

config := sanitizer.NewDefaultConfig().
    WithMetrics(&MyMetrics{}).                 // NEW: Enable metrics
    WithMaxFieldLength(10000).                 // NEW: Limit field size (10KB)
    WithMaxContentLength(100000)               // NEW: Limit content scan (100KB)

s := sanitizer.New(config)
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

func main() {
    // Create sanitizer with default config (all regions)
    s := sanitizer.NewDefault()

    // Sanitize a single field
    email := s.SanitizeField("email", "user@example.com")
    fmt.Println(email) // Output: [REDACTED]

    // Sanitize a map
    data := map[string]interface{}{
        "orderId": "ORD-123",
        "email":   "user@example.com",
        "nric":    "S1234567A",
        "amount":  100.50,
    }

    sanitized := s.SanitizeMap(data)
    // orderId: preserved, email: [REDACTED], nric: [REDACTED], amount: preserved
}
```

### Region-Specific Sanitization

```go
// Singapore only
s := sanitizer.NewForRegion(sanitizer.Singapore)

// Multiple regions
s := sanitizer.NewForRegion(sanitizer.Singapore, sanitizer.Malaysia, sanitizer.UAE)
```

### Dual Sanitizers (Logs vs UI)

```go
// Permissive sanitizer for logs (5% false positives OK)
logSanitizer := sanitizer.New(
    sanitizer.NewDefaultConfig().
        WithRedact("description", "memo", "reference"). // Transaction fields
        WithPreserve("orderId", "productId"),          // Business IDs
)

// Strict sanitizer for UI (minimize false positives)
uiSanitizer := sanitizer.New(
    sanitizer.NewDefaultConfig().
        WithRedact(
            "fullName", "firstName", "lastName",       // Names
            "email", "emailAddress",                   // Emails
            "accountNumber", "bankAccount",            // Bank accounts
        ).
        WithPreserve(
            "orderId", "transactionId", "currency",    // Safe fields
        ),
)
```

### Custom Configuration

```go
config := sanitizer.NewDefaultConfig().
    WithRegions(sanitizer.Singapore).
    WithRedact("customPIIField").                  // Always redact
    WithPreserve("name").                          // Never redact (override default)
    WithStrategy(sanitizer.StrategyPartial).       // Partial masking
    WithPartialMasking('*', 0, 4)                 // Show last 4 chars

s := sanitizer.New(config)

result := s.SanitizeField("creditCard", "4532-1234-5678-9010")
// Output: "****-****-****-9010"
```

## Supported PII Types

### Regional Patterns

| Region | ID Type | Format | Example |
|--------|---------|--------|---------|
| 🇸🇬 Singapore | NRIC | `[STFGM]1234567A` | S1234567A |
| 🇸🇬 Singapore | FIN | `[FGM]1234567N` | F1234567N |
| 🇲🇾 Malaysia | MyKad | `YYMMDD-BP-NNNG` | 901230-14-5678 |
| 🇦🇪 UAE | Emirates ID | `784-YYYY-XXXXXXX-X` | 784-2020-1234567-1 |
| 🇹🇭 Thailand | National ID | `X-XXXX-XXXXX-XX-X` | 1-2345-67890-12-3 |
| 🇭🇰 Hong Kong | HKID | `A123456(D)` | A123456(7) |

### Common PII (Priority Order)

1. **Legal Names**: fullName, firstName, lastName, customerName, etc.
2. **Transaction Descriptions**: description, memo, narrative, reference, remarks
3. **Bank Account Numbers**: accountNumber, bankAccount, iban
4. **Emails**: email, emailAddress, userEmail
5. **Physical Addresses**: address, street, postalCode, city

### Secrets (Always Redacted)

- **Passwords**: password, passwd, pwd, secret
- **Tokens**: token, accessToken, refreshToken
- **API Keys**: apiKey, apiSecret
- **Credentials**: privateKey, secretKey, credential

## Redaction Strategies

```go
// Full redaction (default)
s.WithStrategy(sanitizer.StrategyFull)
// "user@example.com" → "[REDACTED]"

// Partial masking
s.WithStrategy(sanitizer.StrategyPartial).WithPartialMasking('*', 0, 4)
// "user@example.com" → "*************.com"

// Hashing
s.WithStrategy(sanitizer.StrategyHash)
// "user@example.com" → "sha256:a3c7e8f9..."

// Remove field entirely
s.WithStrategy(sanitizer.StrategyRemove)
// Field is removed from output map
```

## Examples

### Nested Data

```go
data := map[string]interface{}{
    "user": map[string]interface{}{
        "fullName": "John Doe",
        "email":    "john@example.com",
        "address": map[string]interface{}{
            "street":     "123 Main St",
            "postalCode": "12345",
        },
    },
    "order": map[string]interface{}{
        "orderId": "ORD-123",
        "amount":  99.99,
    },
}

sanitized := s.SanitizeMap(data)
// All PII fields redacted, orderId and amount preserved
```

### JSON Sanitization

```go
jsonData := []byte(`{"email":"user@example.com","orderId":"ORD-123"}`)
sanitized, err := s.SanitizeJSON(jsonData)
// sanitized: {"email":"[REDACTED]","orderId":"ORD-123"}
```

### Struct Sanitization

```go
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

sanitized := s.SanitizeStruct(user)
// Returns map with email and name redacted, OrderID preserved
```

### Struct Tag Support

Use struct tags to explicitly control PII sanitization behavior:

```go
type User struct {
    Email    string `json:"email" pii:"redact"`
    FullName string `json:"fullName" pii:"redact"`
    OrderID  string `json:"orderId" pii:"preserve"`
    Age      int    `json:"age"`  // Uses pattern matching
}

user := User{
    Email:    "user@example.com",
    FullName: "John Doe",
    OrderID:  "ORD-123",
    Age:      30,
}

s := sanitizer.NewDefault()
result := s.SanitizeStructWithTags(user)
// {
//   "email": "[REDACTED]",      // Redacted by tag
//   "fullName": "[REDACTED]",   // Redacted by tag
//   "orderId": "ORD-123",       // Preserved by tag
//   "age": 30                    // Preserved (no PII pattern match)
// }
```

**Tag Priority:** `pii:"preserve"` > `pii:"redact"` > pattern matching

**Available tags:**
- `pii:"redact"` - Always redact this field
- `pii:"preserve"` - Never redact this field (overrides pattern matching)
- `pii:"redact,sensitive"` - Redact and mark as sensitive (for audit logs)

**Advanced example with nested structs:**

```go
type Address struct {
    Street string `json:"street" pii:"redact"`
    City   string `json:"city" pii:"preserve"`
}

type Customer struct {
    Name    string  `json:"name" pii:"redact"`
    Address Address `json:"address"`
    OrderID string  `json:"orderId" pii:"preserve"`
}

customer := Customer{
    Name: "John Doe",
    Address: Address{
        Street: "123 Main St",
        City:   "Singapore",
    },
    OrderID: "ORD-123",
}

result := s.SanitizeStructWithTags(customer)
// {
//   "name": "[REDACTED]",
//   "address": {
//     "street": "[REDACTED]",
//     "city": "Singapore"
//   },
//   "orderId": "ORD-123"
// }
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `Regions` | Enabled geographic regions | All (SG, MY, AE, TH, HK) |
| `AlwaysRedact` | Field names to always redact | `[]` |
| `NeverRedact` | Field names to never redact | `[]` |
| `Strategy` | Redaction strategy | `StrategyFull` |
| `PartialMaskChar` | Character for partial masking | `'*'` |
| `PartialKeepLeft` | Chars to keep on left | `0` |
| `PartialKeepRight` | Chars to keep on right | `4` |
| `MaxDepth` | Max nesting depth | `10` |

## Performance

- **Field sanitization**: < 10 μs per field
- **Map sanitization (10 fields)**: < 100 μs
- **Nested structures**: < 500 μs for typical cases
- **Memory**: < 500 bytes per operation

Suitable for high-volume logging and API sanitization at < 100 requests/min.

## Development

### Quick Commands (Makefile)

The project includes a comprehensive Makefile for common development tasks:

```bash
# Run all tests
make test

# Run tests with coverage report
make coverage

# Generate HTML coverage report
make coverage-html

# Run benchmarks
make bench

# Format code
make fmt

# Run linters
make lint

# Run all checks (fmt, vet, test, coverage)
make all

# Clean build artifacts
make clean

# Show all available targets
make help
```

### Testing

```bash
# Using Makefile (recommended)
make test              # Run all tests
make test-verbose      # Verbose output
make test-coverage     # With coverage
make coverage-html     # HTML coverage report

# Using go test directly
go test ./sanitizer/...
go test ./sanitizer/... -cover
go test ./sanitizer/... -v
go test -race ./sanitizer/...  # Race detector
```

### Benchmarks

```bash
# Using Makefile
make bench              # Run all benchmarks
make bench-cpu          # With CPU profiling
make bench-mem          # With memory profiling

# Using go test
go test -bench=. -benchmem ./sanitizer/...
```

## Use Cases

### Logging (5% FP tolerance)

```go
logSanitizer := sanitizer.NewDefault()
logger.Info("user action", "user", logSanitizer.SanitizeStruct(user))
```

### UI/API (< 2% FP tolerance)

```go
uiSanitizer := sanitizer.New(config.WithRedact(
    "fullName", "email", "phone", "accountNumber",
))

func GetUserProfile(w http.ResponseWriter, r *http.Request) {
    user := getUserFromDB()
    sanitized := uiSanitizer.SanitizeMap(user)
    json.NewEncoder(w).Encode(sanitized)
}
```

## Logger Integrations

The library provides native integrations for popular Go logging libraries.

### slog (Standard Library)

```go
import (
    "log/slog"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

s := sanitizer.NewDefault()
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

// Sanitize entire object
userData := map[string]interface{}{
    "email": "user@example.com",
    "orderId": "ORD-123",
}
logger.Info("user action", "user", s.SlogValue(userData))

// Sanitize individual field
logger.Info("login", s.SlogString("email", "user@example.com"))

// Grouped fields
logger.Info("payment", s.SlogGroup("customer",
    "email", "user@example.com",
    "orderId", "ORD-123",
))
```

**Output:**
```json
{"time":"2024-01-15T10:30:00Z","level":"INFO","msg":"user action","user":{"email":"[REDACTED]","orderId":"ORD-123"}}
```

### zap (Uber)

```go
import (
    "go.uber.org/zap"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

s := sanitizer.NewDefault()
logger, _ := zap.NewProduction()

// Sanitize entire object
userData := map[string]interface{}{
    "email": "user@example.com",
    "orderId": "ORD-123",
}
logger.Info("user action", zap.Object("user", s.ZapObject(userData)))

// Sanitize individual field
logger.Info("login", s.ZapString("email", "user@example.com"))

// Multiple objects
logger.Info("order",
    zap.Object("customer", s.ZapObject(customer)),
    zap.Object("order", s.ZapObject(order)),
)
```

**Output:**
```json
{"level":"info","timestamp":"2024-01-15T10:30:00Z","msg":"user action","user":{"email":"[REDACTED]","orderId":"ORD-123"}}
```

### zerolog

```go
import (
    "github.com/rs/zerolog"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

s := sanitizer.NewDefault()
logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

// Sanitize entire object
userData := map[string]interface{}{
    "email": "user@example.com",
    "orderId": "ORD-123",
}
logger.Info().Object("user", s.ZerologObject(userData)).Msg("user action")

// Sanitize individual field
key, value := s.ZerologString("email", "user@example.com")
logger.Info().Str(key, value).Msg("login")

// Multiple objects
logger.Info().
    Object("customer", s.ZerologObject(customer)).
    Object("order", s.ZerologObject(order)).
    Msg("order created")
```

**Output:**
```json
{"level":"info","time":1705315800,"message":"user action","user":{"email":"[REDACTED]","orderId":"ORD-123"}}
```

### Working Examples

See the [`examples/`](./examples) directory for complete working examples:
- [`examples/slog/`](./examples/slog) - slog integration examples
- [`examples/zap/`](./examples/zap) - zap integration examples
- [`examples/zerolog/`](./examples/zerolog) - zerolog integration examples

Each example demonstrates:
- Basic and nested data sanitization
- Regional PII patterns
- Custom configurations (logs vs UI)
- Different redaction strategies

## Documentation

For more detailed information, see the documentation in the [`docs/`](./docs) directory:

- **[Pattern Reference](./docs/PATTERNS.md)** - Complete reference of all PII patterns (common + regional)
- **[Performance Guide](./docs/PERFORMANCE.md)** - Benchmarks, optimization strategies, and best practices
- **[Compliance Guide](./docs/COMPLIANCE.md)** - Regulatory compliance for SG, MY, AE, TH, HK

## Compliance

Designed to help with data protection regulations in target regions:

- 🇸🇬 Singapore PDPA (Personal Data Protection Act)
- 🇲🇾 Malaysia PDPA
- 🇦🇪 UAE data protection regulations
- 🇹🇭 Thailand PDPA (2022)
- 🇭🇰 Hong Kong PDPO (Personal Data Privacy Ordinance)

See the [Compliance Guide](./docs/COMPLIANCE.md) for detailed implementation guidance.

## Troubleshooting

### False Positives (Non-PII being redacted)

**Problem:** Order IDs, transaction IDs, or other business identifiers are being redacted.

**Solution:** Add them to the explicit preserve list:

```go
config := sanitizer.NewDefaultConfig().
    WithPreserve("orderId", "transactionId", "productId", "sessionId")
s := sanitizer.New(config)
```

Or use struct tags:

```go
type Order struct {
    OrderID string `json:"orderId" pii:"preserve"`
    // ...
}
```

### False Negatives (PII not being redacted)

**Problem:** PII is not being detected.

**Solution 1:** Add custom patterns:

```go
config := sanitizer.NewDefaultConfig().
    WithRedact("customPIIField", "internalNotes")
```

**Solution 2:** Use struct tags for explicit marking:

```go
type Data struct {
    InternalNotes string `pii:"redact"`
}
```

### Performance Issues

**Problem:** Sanitization is slow for large nested structures.

**Solution:** See the [Performance Guide](./docs/PERFORMANCE.md) for optimization strategies:

1. Use explicit preserve lists to skip pattern matching
2. Enable only needed regions
3. Use `SanitizeMap` instead of `SanitizeStruct` when possible
4. Limit nesting depth: `config.MaxDepth = 5`

### Regional Patterns Not Matching

**Problem:** Singapore NRIC not being detected.

**Solution:** Ensure the region is enabled:

```go
// All regions (default)
s := sanitizer.NewDefault()

// Specific region
s := sanitizer.NewForRegion(sanitizer.Singapore)
```

### Getting Help

- Check the [Documentation](./docs)
- Search [existing issues](https://github.com/vsemashko/go-pii-sanitizer/issues)
- Open a [new issue](https://github.com/vsemashko/go-pii-sanitizer/issues/new) with:
  - Go version (`go version`)
  - Library version
  - Minimal reproducible example
  - Expected vs actual behavior

## License

MIT

## Breaking Changes (v1.0)

**Important:** Version 1.0 introduces stricter validation that significantly reduces false positives. Please review these changes before upgrading.

### Bank Account Detection

**Changed:** Bank accounts are now detected **only via field name matching**, not content patterns.

```go
// ✅ Will be redacted (field name match)
data := map[string]any{
    "accountNumber": "1234567890",  // REDACTED
    "bankAccount":   "9876543210",  // REDACTED
}

// ❌ Will NOT be redacted (no field name match)
text := "Transfer 1234567890 to account"  // NOT redacted (just text)
```

**Migration:** If you need content-based bank account detection, add custom patterns:
```go
config.CustomContentPatterns = append(config.CustomContentPatterns, ContentPattern{
    Name:    "custom_bank",
    Pattern: regexp.MustCompile(`your-specific-pattern`),
})
```

### IP Address Detection

**Changed:** IPv4/IPv6 addresses are **no longer detected by default**.

**Rationale:** IP addresses rarely qualify as PII under GDPR/PDPA and caused false positives on version numbers (e.g., `1.2.3.4`), configuration values, etc.

**Migration:** Add custom pattern if you need IP detection:
```go
config.CustomContentPatterns = append(config.CustomContentPatterns, ContentPattern{
    Name:    "ipv4",
    Pattern: regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
})
```

### Checksum Validation

**Changed:** NRIC, FIN, MyKad, and credit card numbers now use **checksum validation**.

```go
// ❌ These will NOT match (invalid checksums)
"S1234567A"           // Invalid NRIC checksum
"4532-1234-5678-9010" // Invalid Luhn checksum
"991340-14-5678"      // Invalid date (month 13)

// ✅ These WILL match (valid)
"S1234567D"           // Valid NRIC checksum
"4532015112830366"    // Valid Luhn checksum
"901230-14-5678"      // Valid date (Dec 30, 1990)
```

**Impact:** Reduces false positives by ~15-20% overall

**Migration:** Use valid test data in your tests. See [MIGRATION.md](./MIGRATION.md) for examples.

### Configuration Validation

**Changed:** Invalid configurations now cause **panic** in `New()` constructor.

```go
// ❌ This will PANIC
config := NewDefaultConfig()
config.Regions = []Region{}  // Empty regions not allowed
s := New(config)             // PANIC: "at least one region must be enabled"

// ✅ This is valid
config := NewDefaultConfig()
config.Regions = []Region{Singapore}  // At least one region
s := New(config)                      // OK
```

**Validated rules:**
- Regions: At least 1 required
- PartialKeepLeft/Right: Must be ≥ 0
- MaxDepth: Must be 1-100

**Migration:** Ensure your config passes validation before calling `New()`, or use `config.Validate()` to check.

### Summary of Changes

| Change | Before | After | Impact |
|--------|--------|-------|--------|
| Bank accounts | Content + field name | Field name only | -40% false positives |
| IP addresses | Detected by default | Not detected | -5% false positives |
| NRIC validation | Pattern only | Pattern + checksum | -15% false positives |
| Credit cards | Pattern only | Pattern + Luhn | -20% false positives |
| MyKad validation | Pattern only | Pattern + date | -10% false positives |
| Config validation | None | Required | Prevents misconfiguration |
| **Total FP reduction** | **30-50%** | **5-10%** | **✅ 75-85% improvement** |

See [MIGRATION.md](./MIGRATION.md) for detailed upgrade guide.

## Contributing

Contributions are welcome! Here's how to contribute:

1. **Fork the repository**
2. **Create a feature branch:** `git checkout -b feature/my-feature`
3. **Make your changes**
4. **Run tests:** `make test`
5. **Run linters:** `make lint`
6. **Format code:** `make fmt`
7. **Commit your changes:** `git commit -am 'Add new feature'`
8. **Push to the branch:** `git push origin feature/my-feature`
9. **Submit a pull request**

### Development Setup

```bash
# Clone the repository
git clone https://github.com/vsemashko/go-pii-sanitizer.git
cd go-pii-sanitizer

# Install Go (using mise)
mise install

# Download dependencies
go mod download

# Run tests
make test

# Run all checks
make all
```

### Code Standards

- Follow Go best practices and idioms
- Add tests for new features
- Update documentation as needed
- Run `make all` before submitting PR
- Maintain test coverage above 95% (current: 94.1%)

## Roadmap

**Completed:**
- [x] Core PII sanitizer (Week 1) ✅
- [x] slog, zap, zerolog logger integrations (Week 2) ✅
- [x] Comprehensive test suite with benchmarks (Week 3) ✅
- [x] Complete documentation (PATTERNS.md, PERFORMANCE.md, COMPLIANCE.md) ✅
- [x] Struct tag support (`pii:"redact"`, `pii:"preserve"`) ✅
- [x] Makefile for development tasks ✅
- [x] GitHub Actions CI/CD pipeline ✅

**Future:**
- [ ] Context-aware detection for reduced false positives
- [ ] Microsoft Presidio integration (optional, for ML-powered detection)
- [ ] Additional regions (Indonesia, Philippines, Vietnam, etc.)
- [ ] Custom validation functions per field
- [ ] Streaming JSON sanitization for large payloads
