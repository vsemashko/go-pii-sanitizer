# PII Sanitizer for Go - Implementation Plan (Revised)

## Executive Summary

This document outlines a **lean, focused implementation** for a production-ready PII sanitization utility for Go, targeting **Singapore, Malaysia, UAE, Thailand, and Hong Kong** markets. The library provides seamless integration with popular Go logging libraries (slog, zap, zerolog) with minimal performance overhead.

**Philosophy**: Start with an MVP that solves 80% of use cases, then iterate based on real-world feedback.

## Research Findings

### Go Logging Ecosystem

The Go logging landscape is dominated by three libraries:

1. **log/slog** (Standard Library, Go 1.21+) - ⭐️⭐️⭐️
   - `slog.LogValuer` interface provides **zero-overhead** custom field marshaling
   - Becoming the standard for structured logging
   - **PRIMARY TARGET for integration**

2. **uber-go/zap** (~23,800 GitHub stars) - ⭐️⭐️⭐️
   - Most popular third-party structured logging library
   - `zapcore.ObjectMarshaler` interface for custom marshaling
   - Minimal overhead when used correctly

3. **rs/zerolog** (~11,900 GitHub stars) - ⭐️⭐️
   - Zero-allocation design, fastest in benchmarks
   - Chainable API

### Gap Analysis

**Existing PII libraries have very low adoption**:
- `cockroachdb/redact` - 36 stars
- Other Go PII libraries - < 100 stars each

**Key Insight**: No well-established, production-ready PII sanitization solution exists for Go. This is an opportunity.

### Critical Findings

1. **Reflection-based approaches** add significant overhead (2.5x latency increase)
2. **Interface-based approaches** (`slog.LogValuer`, `zapcore.ObjectMarshaler`) have minimal/zero overhead
3. Existing solutions are **US-centric** (SSN, ZIP codes) - not relevant for APAC/ME markets
4. **Pattern matching + explicit configuration** can achieve 95%+ accuracy without ML

## Target Regions & Compliance

### Geographic Focus

- 🇸🇬 **Singapore** - PDPA (Personal Data Protection Act)
- 🇲🇾 **Malaysia** - PDPA (similar to Singapore)
- 🇦🇪 **UAE** - GDPR-influenced regulations
- 🇹🇭 **Thailand** - PDPA (2022)
- 🇭🇰 **Hong Kong** - PDPO (Personal Data Privacy Ordinance)

### Key Regulations

**Singapore PDPA (strictest)**:
- NRIC numbers should NOT be used as identifiers in logs or UIs
- Mandatory breach notification
- Organizations must minimize PII collection

**Common requirements across regions**:
- Consent for collection
- Right to access and deletion
- Security safeguards
- Breach notification

## Architecture Overview (Simplified)

```
┌──────────────────────────────────────────────┐
│          PII Sanitizer Core                  │
├──────────────────────────────────────────────┤
│                                              │
│  ┌────────────────┐   ┌──────────────────┐ │
│  │ Pattern        │   │  Redaction       │ │
│  │ Matcher        │   │  Engine          │ │
│  │                │   │                  │ │
│  │ • Field names  │   │  • Full mask     │ │
│  │ • Content      │   │  • Partial mask  │ │
│  │ • Regional IDs │   │  • Hash          │ │
│  └────────────────┘   └──────────────────┘ │
│                                              │
│  ┌──────────────────────────────────────┐  │
│  │  Configuration                        │  │
│  │  • Explicit allow/deny lists          │  │
│  │  • Regional patterns (SG/MY/AE/TH/HK)│  │
│  │  • Custom patterns                    │  │
│  └──────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
┌────────┐    ┌─────────┐    ┌──────────┐
│  slog  │    │   zap   │    │ zerolog  │
│wrapper │    │ wrapper │    │  wrapper │
└────────┘    └─────────┘    └──────────┘
```

**Key Principles**:
- **Single responsibility**: Pattern matching and redaction only
- **Zero/minimal overhead**: Leverage native interfaces
- **Simple configuration**: Sensible defaults, explicit overrides
- **Extensible**: Easy to add new patterns and regions

## Regional PII Patterns

### Singapore 🇸🇬

```go
type SingaporePatterns struct {
    NRIC  string // National Registration Identity Card
    FIN   string // Foreign Identification Number
    Phone string // +65 format
}

var SG = SingaporePatterns{
    // Format: [STFGM]1234567A (prefix + 7 digits + checksum)
    NRIC: `(?i)\b[STFGM]\d{7}[A-Z]\b`,

    // Foreign Identification Number (similar format)
    FIN: `(?i)\b[FGM]\d{7}[A-Z]\b`,

    // Phone: +65 [689]XXXXXXX (8 digits total)
    Phone: `(?:\+65|65)?[689]\d{7}`,
}

// Field name patterns
var SGFieldNames = []string{
    "nric", "ic", "identityCard", "identity_card",
    "fin", "foreignId", "foreign_id",
}
```

### Malaysia 🇲🇾

```go
type MalaysiaPatterns struct {
    MyKad string // Malaysian Identity Card
    Phone string
}

var MY = MalaysiaPatterns{
    // Format: YYMMDD-BP-NNNG (12 digits with dashes)
    // Or: YYMMDDBBNNNG (12 digits without dashes)
    MyKad: `\b\d{6}-?\d{2}-?\d{4}\b`,

    // Phone: +60 / 60 / 0 + prefix + number
    // 01X-XXX-XXXX or 01X-XXXXXXXX (depending on prefix)
    Phone: `(?:\+?60|0)1[0-46-9]\d{7,8}`,
}

var MYFieldNames = []string{
    "mykad", "ic", "icNumber", "myKadNumber",
    "identityCard", "identity_card", "malaysianId",
}
```

### UAE 🇦🇪

```go
type UAEPatterns struct {
    EmiratesID string
    Phone      string
}

var AE = UAEPatterns{
    // Format: 784-YYYY-XXXXXXX-X (15 digits)
    // Often written without dashes: 784YYYYXXXXXXXD
    EmiratesID: `\b784-?\d{4}-?\d{7}-?\d\b`,

    // Phone: +971 or 00971 or 0 + area/mobile code + 7 digits
    Phone: `(?:\+971|00971|0)(?:2|3|4|6|7|9|50|51|52|54|55|56|58)\d{7}`,
}

var AEFieldNames = []string{
    "emiratesId", "emirates_id", "eid", "uaeId",
    "identityCard", "identity_card", "nationalId",
}
```

### Thailand 🇹🇭

```go
type ThailandPatterns struct {
    NationalID string
    Phone      string
}

var TH = ThailandPatterns{
    // Format: 13 digits (X-XXXX-XXXXX-XX-X with check digit)
    NationalID: `\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b`,

    // Phone: +66 followed by 8-9 digits (mobile: 6/8/9 prefix)
    Phone: `(?:\+66|66|0)[689]\d{8}`,
}

var THFieldNames = []string{
    "thaiId", "thai_id", "nationalId", "national_id",
    "idCard", "id_card", "citizenId",
}
```

### Hong Kong 🇭🇰

```go
type HongKongPatterns struct {
    HKID  string
    Phone string
}

var HK = HongKongPatterns{
    // Format: A123456(D) - 1 or 2 letters + 6 digits + check digit (0-9 or A)
    HKID: `(?i)\b[A-Z]{1,2}\d{6}\([A0-9]\)|\b[A-Z]{1,2}\d{6}[A0-9]\b`,

    // Phone: +852 followed by 8 digits (mobile: 5/6/9 prefix)
    Phone: `(?:\+852|852)?[5-9]\d{7}`,
}

var HKFieldNames = []string{
    "hkid", "identityCard", "identity_card",
    "hongkongId", "hongkong_id",
}
```

### Common Patterns (All Regions)

```go
type CommonPatterns struct {
    Email      string
    CreditCard string
    IPv4       string
    IPv6       string
}

var Common = CommonPatterns{
    // RFC 5322 simplified
    Email: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,

    // Credit card: 13-19 digits, optional spaces/dashes
    // Includes Luhn validation in code
    CreditCard: `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,3}\b`,

    // IPv4
    IPv4: `\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,

    // IPv6 (simplified)
    IPv6: `(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b`,
}

// Common PII field names
var CommonFieldNames = map[string][]string{
    "email": {
        "email", "e_mail", "emailAddress", "email_address", "mail",
    },
    "phone": {
        "phone", "phoneNumber", "phone_number", "mobile", "mobileNumber",
        "telephone", "tel", "contact", "contactNumber",
    },
    "address": {
        "address", "street", "streetAddress", "homeAddress",
        "mailingAddress", "postalCode", "postal_code", "postCode",
    },
    "passport": {
        "passport", "passportNumber", "passport_number", "passportNo",
    },
    "dob": {
        "dateOfBirth", "date_of_birth", "dob", "birthDate", "birth_date",
        "birthday",
    },
    "name": {
        // Context-sensitive: only redact in user/customer contexts
        "fullName", "full_name", "legalName", "legal_name",
        "firstName", "first_name", "lastName", "last_name",
        "surname", "givenName", "given_name",
    },
    "creditCard": {
        "creditCard", "credit_card", "cardNumber", "card_number",
        "ccNumber", "cc_number", "paymentCard", "payment_card",
    },
}

// Secrets (always redact)
var SecretFieldNames = []string{
    "password", "passwd", "pwd", "secret",
    "token", "accessToken", "access_token", "refreshToken", "refresh_token",
    "apiKey", "api_key", "apiSecret", "api_secret",
    "privateKey", "private_key", "secretKey", "secret_key",
    "credential", "credentials", "auth", "authorization",
    "bearer", "sessionId", "session_id",
}
```

## Core Implementation

### Configuration

```go
package sanitizer

type Config struct {
    // Region selection (default: all enabled)
    Regions []Region // SG, MY, AE, TH, HK

    // Explicit lists (highest priority)
    AlwaysRedact  []string // Field names to always redact
    NeverRedact   []string // Field names to never redact (allowlist)

    // Redaction strategy
    Strategy RedactionStrategy // Full, Partial, Hash (default: Full)

    // For partial masking
    PartialMaskChar rune // Default: '*'
    PartialKeepLeft int  // Default: 0
    PartialKeepRight int // Default: 4

    // Performance tuning
    MaxDepth int // Max nesting depth for traversal (default: 10)

    // Custom patterns (advanced)
    CustomFieldPatterns  map[string][]string
    CustomContentPatterns []ContentPattern
}

type Region string

const (
    Singapore  Region = "SG"
    Malaysia   Region = "MY"
    UAE        Region = "AE"
    Thailand   Region = "TH"
    HongKong   Region = "HK"
)

type RedactionStrategy string

const (
    StrategyFull    RedactionStrategy = "full"    // "[REDACTED]"
    StrategyPartial RedactionStrategy = "partial" // "****1234"
    StrategyHash    RedactionStrategy = "hash"    // "sha256:abc..."
    StrategyRemove  RedactionStrategy = "remove"  // Remove field entirely
)

type ContentPattern struct {
    Name      string
    Pattern   *regexp.Regexp
    Validator func(string) bool // Optional (e.g., Luhn for credit cards)
}

// Smart defaults
func NewDefaultConfig() *Config {
    return &Config{
        Regions:         []Region{Singapore, Malaysia, UAE, Thailand, HongKong},
        AlwaysRedact:    []string{},
        NeverRedact:     []string{},
        Strategy:        StrategyFull,
        PartialMaskChar: '*',
        PartialKeepLeft: 0,
        PartialKeepRight: 4,
        MaxDepth:        10,
    }
}

// Fluent configuration
func (c *Config) WithRedact(fields ...string) *Config {
    c.AlwaysRedact = append(c.AlwaysRedact, fields...)
    return c
}

func (c *Config) WithPreserve(fields ...string) *Config {
    c.NeverRedact = append(c.NeverRedact, fields...)
    return c
}

func (c *Config) WithStrategy(strategy RedactionStrategy) *Config {
    c.Strategy = strategy
    return c
}

func (c *Config) WithRegions(regions ...Region) *Config {
    c.Regions = regions
    return c
}
```

### Core Sanitizer

```go
package sanitizer

type Sanitizer struct {
    config          *Config
    fieldPatterns   map[string]*regexp.Regexp // Compiled field name patterns
    contentPatterns []ContentPattern           // Compiled content patterns
}

func New(config *Config) *Sanitizer {
    if config == nil {
        config = NewDefaultConfig()
    }

    s := &Sanitizer{
        config:          config,
        fieldPatterns:   make(map[string]*regexp.Regexp),
        contentPatterns: []ContentPattern{},
    }

    s.compilePatterns()
    return s
}

// NewDefault creates a sanitizer with default config for all regions
func NewDefault() *Sanitizer {
    return New(NewDefaultConfig())
}

// NewForRegion creates a sanitizer for specific region(s)
func NewForRegion(regions ...Region) *Sanitizer {
    config := NewDefaultConfig()
    config.Regions = regions
    return New(config)
}

func (s *Sanitizer) compilePatterns() {
    // Compile field name patterns
    // Compile content patterns based on enabled regions
    // Cache compiled regexes for performance
}

// SanitizeField sanitizes a single field value
func (s *Sanitizer) SanitizeField(fieldName, value string) string {
    // 1. Check explicit lists first (AlwaysRedact, NeverRedact)
    // 2. Check field name patterns
    // 3. Check content patterns
    // 4. Apply redaction strategy if PII detected
}

// SanitizeMap sanitizes a map (common for JSON-like structures)
func (s *Sanitizer) SanitizeMap(m map[string]interface{}) map[string]interface{} {
    return s.sanitizeMapRecursive(m, 0)
}

func (s *Sanitizer) sanitizeMapRecursive(m map[string]interface{}, depth int) map[string]interface{} {
    if depth > s.config.MaxDepth {
        return m
    }

    result := make(map[string]interface{})
    for k, v := range m {
        switch val := v.(type) {
        case string:
            result[k] = s.SanitizeField(k, val)
        case map[string]interface{}:
            result[k] = s.sanitizeMapRecursive(val, depth+1)
        case []interface{}:
            result[k] = s.sanitizeSlice(val, depth+1)
        default:
            result[k] = val
        }
    }
    return result
}

func (s *Sanitizer) sanitizeSlice(slice []interface{}, depth int) []interface{} {
    // Handle slices recursively
}

// SanitizeJSON is a convenience method for JSON data
func (s *Sanitizer) SanitizeJSON(data []byte) ([]byte, error) {
    var m map[string]interface{}
    if err := json.Unmarshal(data, &m); err != nil {
        return nil, err
    }

    sanitized := s.SanitizeMap(m)
    return json.Marshal(sanitized)
}

// Redaction strategies
func (s *Sanitizer) redact(value string) string {
    switch s.config.Strategy {
    case StrategyFull:
        return "[REDACTED]"
    case StrategyPartial:
        return s.partialMask(value)
    case StrategyHash:
        return s.hashValue(value)
    case StrategyRemove:
        return "" // Signal to remove field
    default:
        return "[REDACTED]"
    }
}

func (s *Sanitizer) partialMask(value string) string {
    if len(value) <= s.config.PartialKeepLeft+s.config.PartialKeepRight {
        // Too short to mask, redact fully
        return strings.Repeat(string(s.config.PartialMaskChar), len(value))
    }

    left := value[:s.config.PartialKeepLeft]
    right := value[len(value)-s.config.PartialKeepRight:]
    masked := strings.Repeat(string(s.config.PartialMaskChar),
        len(value)-s.config.PartialKeepLeft-s.config.PartialKeepRight)

    return left + masked + right
}

func (s *Sanitizer) hashValue(value string) string {
    h := sha256.Sum256([]byte(value))
    return "sha256:" + hex.EncodeToString(h[:8]) // First 8 bytes for brevity
}
```

## Logger Integrations

### slog Integration (PRIMARY)

```go
package sanitizer

import "log/slog"

// Wrap creates an slog.LogValuer that sanitizes the value
func (s *Sanitizer) Wrap(value interface{}) slog.LogValuer {
    return &piiWrapper{sanitizer: s, value: value}
}

type piiWrapper struct {
    sanitizer *Sanitizer
    value     interface{}
}

func (p *piiWrapper) LogValue() slog.Value {
    // Convert value to map/struct and sanitize
    switch v := p.value.(type) {
    case string:
        return slog.StringValue(p.sanitizer.SanitizeField("", v))
    case map[string]interface{}:
        sanitized := p.sanitizer.SanitizeMap(v)
        return slog.AnyValue(sanitized)
    default:
        // Convert struct to map via JSON (avoid reflection)
        data, _ := json.Marshal(v)
        var m map[string]interface{}
        json.Unmarshal(data, &m)
        sanitized := p.sanitizer.SanitizeMap(m)
        return slog.AnyValue(sanitized)
    }
}

// WrapField sanitizes a specific field
func (s *Sanitizer) WrapField(name, value string) slog.Attr {
    return slog.String(name, s.SanitizeField(name, value))
}

// Usage example:
func example() {
    s := sanitizer.NewForRegion(sanitizer.Singapore)

    user := map[string]interface{}{
        "email": "user@example.com",
        "nric": "S1234567A",
        "name": "John Doe",
    }

    slog.Info("user login",
        "user", s.Wrap(user),
        "ip", s.WrapField("ip", "192.168.1.1"))
}
```

### Zap Integration

```go
package sanitizer

import "go.uber.org/zap/zapcore"

// ZapObject implements zapcore.ObjectMarshaler for automatic sanitization
func (s *Sanitizer) ZapObject(obj interface{}) zapcore.ObjectMarshaler {
    return &zapObjectMarshaler{sanitizer: s, obj: obj}
}

type zapObjectMarshaler struct {
    sanitizer *Sanitizer
    obj       interface{}
}

func (z *zapObjectMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
    // Convert to map and sanitize
    data, _ := json.Marshal(z.obj)
    var m map[string]interface{}
    json.Unmarshal(data, &m)

    sanitized := z.sanitizer.SanitizeMap(m)

    // Encode sanitized map
    for k, v := range sanitized {
        switch val := v.(type) {
        case string:
            enc.AddString(k, val)
        case int:
            enc.AddInt(k, val)
        case float64:
            enc.AddFloat64(k, val)
        case bool:
            enc.AddBool(k, val)
        default:
            enc.AddReflected(k, val)
        }
    }
    return nil
}

// Usage with zap
func zapExample() {
    s := sanitizer.NewDefault()
    logger, _ := zap.NewProduction()

    user := User{Email: "test@example.com", NRIC: "S1234567A"}

    logger.Info("user action",
        zap.Object("user", s.ZapObject(user)))
}
```

### Zerolog Integration

```go
package sanitizer

import "github.com/rs/zerolog"

// ZeroLogMarshaler returns a zerolog.LogObjectMarshaler
func (s *Sanitizer) ZeroLogMarshaler(obj interface{}) zerolog.LogObjectMarshaler {
    return zerologMarshaler{sanitizer: s, obj: obj}
}

type zerologMarshaler struct {
    sanitizer *Sanitizer
    obj       interface{}
}

func (z zerologMarshaler) MarshalZerologObject(e *zerolog.Event) {
    // Similar to zap implementation
    data, _ := json.Marshal(z.obj)
    var m map[string]interface{}
    json.Unmarshal(data, &m)

    sanitized := z.sanitizer.SanitizeMap(m)

    for k, v := range sanitized {
        e.Interface(k, v)
    }
}

// Hook for automatic sanitization
type SanitizerHook struct {
    sanitizer *Sanitizer
}

func (h SanitizerHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
    // Intercept and sanitize
}
```

## Implementation Phases (SIMPLIFIED)

### Phase 1: Core Implementation (Week 1)

**Deliverables**:
- Project structure, go.mod, basic build setup
- Configuration system with sensible defaults
- Regional pattern definitions (SG, MY, AE, TH, HK)
- Common pattern definitions (email, credit card, phone, IP)
- Field name matcher
- Content pattern matcher
- Redaction engine (full, partial, hash strategies)
- Unit tests for pattern matching

**Files**:
```
sanitizer/
├── sanitizer.go       # Core Sanitizer type
├── config.go          # Configuration
├── patterns.go        # Pattern definitions
├── patterns_sg.go     # Singapore patterns
├── patterns_my.go     # Malaysia patterns
├── patterns_ae.go     # UAE patterns
├── patterns_th.go     # Thailand patterns
├── patterns_hk.go     # Hong Kong patterns
├── patterns_common.go # Common patterns (email, etc.)
├── matcher.go         # Pattern matching logic
├── redactor.go        # Redaction strategies
└── sanitizer_test.go
```

### Phase 2: Logger Integration (Week 2)

**Deliverables**:
- slog.LogValuer integration (primary)
- zapcore.ObjectMarshaler integration
- zerolog.LogObjectMarshaler integration
- Helper functions for each logger
- Integration tests with real loggers
- Example applications for each logger

**Files**:
```
sanitizer/
├── slog.go           # slog integration
├── zap.go            # zap integration
├── zerolog.go        # zerolog integration
└── examples/
    ├── example_slog.go
    ├── example_zap.go
    └── example_zerolog.go
```

**Performance target**: < 5% overhead vs logging without sanitization

### Phase 3: Testing, Docs, Benchmarks (Week 3)

**Deliverables**:
- Comprehensive unit tests (> 90% coverage)
- Benchmark tests for all critical paths
- Performance profiling and optimization
- README with usage examples
- GoDoc documentation
- EXAMPLES.md with real-world scenarios
- Docker Compose for local testing (optional Presidio setup for future)

**Files**:
```
sanitizer/
├── sanitizer_test.go
├── benchmark_test.go
├── README.md
├── EXAMPLES.md
└── docs/
    ├── PATTERNS.md      # Pattern reference
    ├── PERFORMANCE.md   # Performance guide
    └── COMPLIANCE.md    # PDPA/PDPO compliance notes
```

**Performance targets**:
- Field sanitization: < 10 μs per field
- Map sanitization (10 fields): < 100 μs
- Nested structure (5 levels, 50 fields): < 500 μs
- Memory: < 500 bytes allocation per sanitization

### Phase 4: Iteration & Enhancement (Week 4+)

**Based on real-world usage feedback**, consider adding:

1. **Struct tags** (if users want explicit field marking):
   ```go
   type User struct {
       Email string `json:"email" pii:"redact"`
       Name  string `json:"name" pii:"conditional,parent=user"`
       OrderID string `json:"orderId" pii:"preserve"`
   }
   ```

2. **Context-aware detection** (if false positives are high):
   - Parent object type detection
   - Sibling field analysis
   - Configurable context rules

3. **Microsoft Presidio integration** (if pattern matching accuracy < 95%):
   - REST API client
   - Fallback to local patterns
   - Caching layer

4. **Code generation** (if reflection overhead is a concern):
   - Generate type-specific sanitizers
   - Zero-allocation implementations

5. **Additional patterns**:
   - Bank account numbers
   - Tax IDs (region-specific)
   - Vehicle registration numbers
   - Custom enterprise patterns

## API Examples

### Basic Usage

```go
package main

import (
    "log/slog"
    "github.com/yourusername/go-pii-sanitizer/sanitizer"
)

func main() {
    // Create sanitizer with defaults (all regions)
    s := sanitizer.NewDefault()

    // Or specify regions
    s := sanitizer.NewForRegion(sanitizer.Singapore, sanitizer.Malaysia)

    // Configure explicitly
    config := sanitizer.NewDefaultConfig().
        WithRegions(sanitizer.Singapore).
        WithRedact("internal_id", "legacy_field").
        WithPreserve("order_id", "product_name").
        WithStrategy(sanitizer.StrategyPartial)

    s := sanitizer.New(config)

    // Use with slog
    user := map[string]interface{}{
        "email": "john@example.com",
        "nric": "S1234567A",
        "phone": "+6591234567",
        "order_id": "ORD-12345", // preserved
    }

    slog.Info("user checkout",
        "user", s.Wrap(user),
        "cart_total", slog.Float64("total", 99.99))

    // Output:
    // user checkout user=map[email:[REDACTED] nric:[REDACTED] phone:[REDACTED] order_id:ORD-12345] cart_total=99.99
}
```

### Zap Integration

```go
import (
    "go.uber.org/zap"
    "github.com/yourusername/go-pii-sanitizer/sanitizer"
)

func zapExample() {
    s := sanitizer.NewDefault()
    logger, _ := zap.NewProduction()

    type User struct {
        Email string
        NRIC  string
        Name  string
    }

    user := User{
        Email: "test@example.com",
        NRIC:  "S1234567A",
        Name:  "John Doe",
    }

    logger.Info("user login",
        zap.Object("user", s.ZapObject(user)),
        zap.String("ip", "192.168.1.1"))
}
```

### Partial Masking for UI

```go
func uiExample() {
    // For displaying on UI - use partial masking
    config := sanitizer.NewDefaultConfig().
        WithStrategy(sanitizer.StrategyPartial).
        WithRegions(sanitizer.Singapore)

    config.PartialKeepRight = 4 // Show last 4 chars

    s := sanitizer.New(config)

    creditCard := "4532-1234-5678-9010"
    masked := s.SanitizeField("creditCard", creditCard)
    // Result: "****-****-****-9010"

    email := "john.doe@example.com"
    maskedEmail := s.SanitizeField("email", email)
    // Result: "********@example.com" or "j*******@example.com"
}
```

### JSON API Sanitization

```go
func apiExample() {
    s := sanitizer.NewDefault()

    // Sanitize JSON before sending to frontend
    responseData := map[string]interface{}{
        "user": map[string]interface{}{
            "id":    "user123",
            "email": "sensitive@example.com",
            "nric":  "S1234567A",
            "profile": map[string]interface{}{
                "name":    "John Doe",
                "phone":   "+6591234567",
                "address": "123 Main St",
            },
        },
        "order": map[string]interface{}{
            "id":     "ORD-123",
            "total":  99.99,
            "status": "completed",
        },
    }

    sanitized := s.SanitizeMap(responseData)
    json.NewEncoder(w).Encode(sanitized)
}
```

## Testing Strategy

### Unit Tests

```go
func TestSingaporeNRIC(t *testing.T) {
    s := sanitizer.NewForRegion(sanitizer.Singapore)

    tests := []struct{
        name string
        input string
        shouldRedact bool
    }{
        {"Valid NRIC", "My NRIC is S1234567A", true},
        {"FIN", "FIN: F1234567N", true},
        {"No PII", "Order ID: ORD-123", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := s.SanitizeField("text", tt.input)
            if tt.shouldRedact {
                assert.Contains(t, result, "[REDACTED]")
            } else {
                assert.Equal(t, tt.input, result)
            }
        })
    }
}
```

### Benchmarks

```go
func BenchmarkSanitizeField(b *testing.B) {
    s := sanitizer.NewDefault()
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        s.SanitizeField("email", "test@example.com")
    }
}

func BenchmarkSanitizeMap(b *testing.B) {
    s := sanitizer.NewDefault()
    m := map[string]interface{}{
        "email": "test@example.com",
        "phone": "+6591234567",
        "name":  "John Doe",
    }
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        s.SanitizeMap(m)
    }
}
```

### Integration Tests

```go
func TestSlogIntegration(t *testing.T) {
    var buf bytes.Buffer
    logger := slog.New(slog.NewJSONHandler(&buf, nil))
    s := sanitizer.NewForRegion(sanitizer.Singapore)

    user := map[string]interface{}{
        "email": "test@example.com",
        "nric":  "S1234567A",
    }

    logger.Info("test", "user", s.Wrap(user))

    // Verify output doesn't contain PII
    output := buf.String()
    assert.NotContains(t, output, "test@example.com")
    assert.NotContains(t, output, "S1234567A")
    assert.Contains(t, output, "[REDACTED]")
}
```

## Performance Targets

### Latency (P95)

- **Field sanitization**: < 10 μs
- **Small map (10 fields)**: < 100 μs
- **Nested structure (50 fields, 5 levels)**: < 500 μs
- **slog integration overhead**: < 5%
- **zap integration overhead**: < 10%

### Memory

- **Per sanitization**: < 500 bytes allocated
- **Pattern compilation (one-time)**: < 100 KB
- **No memory leaks on repeated use**

### Throughput

- **Logger mode**: > 100,000 sanitizations/second (single core)
- **Should NOT be the bottleneck in logging pipeline**

## Security Considerations

1. **No PII in Error Messages**: Ensure sanitizer itself doesn't leak PII in errors/logs
2. **Regex DoS Protection**: Use timeouts and limits on regex execution
3. **Memory Safety**: Clear sensitive data from memory promptly
4. **Default-Secure**: Over-redact rather than under-redact when uncertain
5. **Audit Trail**: Optionally log what was redacted (categories, not values)
6. **No Persistence**: Don't store or cache raw PII values

## Dependencies

### Required

- **Go 1.21+** (for log/slog support)
- **Standard library only** for core functionality

### Optional (for integrations)

- `go.uber.org/zap` - for Zap integration
- `github.com/rs/zerolog` - for Zerolog integration

### Testing

- `github.com/stretchr/testify` - assertions and test utilities

## Future Enhancements (Post-MVP)

### V2 Features (Based on Feedback)

1. **Struct Tags**
   ```go
   type User struct {
       Email string `pii:"redact"`
       Name  string `pii:"conditional,context=user"`
   }
   ```

2. **Context-Aware Detection**
   - Analyze parent object types
   - Check sibling fields for PII indicators
   - Reduce "name" field false positives

3. **Code Generation**
   - Generate type-specific sanitizers
   - Zero reflection, zero allocation
   - CLI tool: `go generate` compatible

4. **Microsoft Presidio Integration**
   - REST API client for ML-powered detection
   - Fallback to local patterns
   - Caching layer for repeated content

5. **Additional Regional Support**
   - Indonesia (KTP)
   - Philippines (PhilSys ID)
   - Vietnam (CCCD)
   - South Korea (주민등록번호)
   - Japan (マイナンバー)

6. **Enterprise Features**
   - Policy-based configuration (YAML/JSON)
   - Centralized pattern management
   - Metrics and observability hooks
   - OpenTelemetry integration

## Success Metrics

### Adoption

- Easy integration: < 5 lines of code for basic use
- Clear documentation with examples
- Positive feedback from early adopters

### Performance

- < 5% overhead in logger mode
- < 100ms P95 for UI sanitization
- Zero memory leaks

### Accuracy

- > 95% detection rate for defined patterns
- < 5% false positive rate
- Zero false negatives for explicit config (AlwaysRedact)

### Reliability

- Graceful handling of malformed input
- No crashes or panics
- Comprehensive test coverage (> 90%)

## Conclusion

This plan focuses on delivering a **lean, production-ready MVP** in 3 weeks:

1. **Week 1**: Core pattern matching and redaction for APAC/ME regions
2. **Week 2**: Seamless integration with slog, zap, and zerolog
3. **Week 3**: Testing, benchmarking, documentation

**Key differentiators**:
- **Regional focus**: First Go PII library targeting SG/MY/AE/TH/HK
- **Zero/minimal overhead**: Leverages native logger interfaces
- **Simple yet powerful**: Sensible defaults, explicit overrides
- **Production-ready**: Performance tested, documented, supported

**Post-MVP**: Iterate based on real-world usage. Add complexity (context rules, Presidio, struct tags) only when data shows it's needed.
