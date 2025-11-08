# PII Sanitizer for Go - Implementation Plan

## Executive Summary

This document outlines the design and implementation plan for a production-ready PII (Personally Identifiable Information) sanitizer utility for Go. The library will provide two operational modes: a high-performance mode for structured logging (zap integration) and a high-precision mode for UI data sanitization (with Microsoft Presidio integration).

## Research Findings

### Existing Solutions

1. **Microsoft Presidio** - Production-ready, context-aware PII detection and anonymization
   - Available via REST API (Docker containers: `mcr.microsoft.com/presidio-analyzer`, `mcr.microsoft.com/presidio-anonymizer`)
   - Supports NLP/NER models for high-precision detection
   - Best for precision over performance

2. **Go Libraries**
   - `github.com/ln80/pii` - Struct field-level protection
   - `github.com/AngusGMorrison/logfusc` - Log redaction library
   - `github.com/m-mizutani/masq` - slog redaction utility
   - `github.com/cockroachdb/redact` - Safe/unsafe data separation

3. **Performance Considerations**
   - Reflection-based approaches: significant overhead (4ms → 10ms p95 latency)
   - `zapcore.ObjectMarshaler` interface: minimal overhead
   - `slog.LogValuer` interface: no measurable performance impact

### Key Insights

- **Field Name Matching**: Regex patterns for common PII field names (email, ssn, phone, etc.)
- **Content Detection**: Pattern matching for structured data (emails, credit cards, IPs, SSNs)
- **Context-Aware Detection**: Reduce false positives by analyzing surrounding fields
- **Configurable Policies**: Allow explicit inclusion/exclusion lists

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    PII Sanitizer Core                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │  Field Name      │  │  Content         │                │
│  │  Detector        │  │  Detector        │                │
│  └──────────────────┘  └──────────────────┘                │
│           │                     │                            │
│           └─────────┬───────────┘                           │
│                     ▼                                        │
│         ┌──────────────────────┐                            │
│         │ Context Analyzer     │                            │
│         │ (False Positive      │                            │
│         │  Reduction)          │                            │
│         └──────────────────────┘                            │
│                     │                                        │
├─────────────────────┼────────────────────────────────────────┤
│                     ▼                                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            Configuration Manager                     │   │
│  │  - Explicit redact list                             │   │
│  │  - Explicit preserve list                           │   │
│  │  - Custom patterns                                  │   │
│  │  - Context rules                                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌──────────────┐          ┌──────────────────┐
│ Logger Mode  │          │   UI Mode        │
│ (Zap)        │          │ (Presidio)       │
│              │          │                  │
│ - Fast       │          │ - High Precision │
│ - Regex      │          │ - ML/NLP         │
│ - Pattern    │          │ - REST API       │
│   matching   │          │   integration    │
└──────────────┘          └──────────────────┘
```

## Core Components

### 1. Field Name Detector

**Purpose**: Identify PII fields by their names using configurable patterns.

**Implementation**:
- Compile regex patterns for common PII field names
- Support case-insensitive matching
- Handle common naming conventions (camelCase, snake_case, kebab-case)

**Default Patterns**:
```go
var defaultFieldPatterns = map[string][]string{
    "email":       {"email", "e_mail", "emailAddress", "mail"},
    "phone":       {"phone", "phoneNumber", "mobile", "telephone", "tel"},
    "ssn":         {"ssn", "socialSecurity", "social_security_number"},
    "creditCard":  {"creditCard", "cardNumber", "ccNumber", "payment_card"},
    "address":     {"address", "street", "zipCode", "postalCode", "zip"},
    "passport":    {"passport", "passportNumber", "passport_id"},
    "dob":         {"dateOfBirth", "dob", "birthDate", "birth_date"},
    "taxId":       {"taxId", "tin", "tax_identification"},
    "license":     {"driverLicense", "license", "licenseNumber"},

    // Contextual patterns (require context analysis)
    "name":        {"firstName", "lastName", "surname", "fullName", "legalName", "givenName"},
    "id":          {"userId", "customerId", "patientId", "accountId"},
}
```

**Secrets Detection**:
```go
var secretPatterns = map[string][]string{
    "password":    {"password", "passwd", "pwd", "secret"},
    "token":       {"token", "accessToken", "refreshToken", "apiKey", "api_key"},
    "key":         {"privateKey", "secretKey", "encryptionKey", "private_key"},
    "credential":  {"credential", "credentials", "auth", "authorization"},
}
```

### 2. Content Detector

**Purpose**: Detect PII in field values using regex pattern matching.

**Implementation**:
```go
type ContentPattern struct {
    Name        string
    Pattern     *regexp.Regexp
    Validator   func(string) bool  // Optional validation function
}
```

**Default Content Patterns**:
- **Email**: RFC 5322 simplified pattern
- **Phone**: International formats (US, EU, etc.)
- **SSN**: US format (XXX-XX-XXXX)
- **Credit Card**: Luhn algorithm validation
- **IP Address**: IPv4 and IPv6
- **URL**: HTTP/HTTPS URLs with potential PII in query params
- **Postal Code**: Multiple country formats

**Regex Examples**:
```go
var contentPatterns = []ContentPattern{
    {
        Name:    "email",
        Pattern: regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`),
    },
    {
        Name:    "ssn",
        Pattern: regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
    },
    {
        Name:    "credit_card",
        Pattern: regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
        Validator: validateLuhn,
    },
    {
        Name:    "phone_us",
        Pattern: regexp.MustCompile(`(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}`),
    },
    {
        Name:    "ipv4",
        Pattern: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
    },
}
```

### 3. Context Analyzer

**Purpose**: Reduce false positives by analyzing field context and relationships.

**Context Rules**:

1. **Name Field Analysis**:
   ```go
   type ContextRule struct {
       Field           string
       RequiredContext []string  // Other fields that must be present
       ParentContext   []string  // Parent object names
   }

   // Example: "name" is only PII if:
   // - Parent object is "user", "customer", "patient", "employee"
   // - OR sibling fields include "email", "phone", "address", "ssn"
   nameRule := ContextRule{
       Field: "name",
       RequiredContext: []string{"email", "phone", "address", "ssn", "surname"},
       ParentContext: []string{"user", "customer", "patient", "employee", "person"},
   }
   ```

2. **ID Field Analysis**:
   - Only redact if the ID clearly references a person (userId, customerId)
   - Don't redact generic IDs (orderId, productId, transactionId)

3. **Hierarchical Context**:
   ```go
   // Track object hierarchy during traversal
   type Context struct {
       Path        []string  // e.g., ["response", "user", "profile"]
       SiblingKeys []string  // Keys at the same level
       ParentType  string    // Parent object identifier
   }
   ```

### 4. Configuration Manager

**Purpose**: Allow users to customize sanitization behavior.

**Configuration Structure**:
```go
type Config struct {
    // Mode selection
    Mode SanitizerMode  // Logger or UI

    // Explicit lists
    RedactFields    []string  // Always redact these fields
    PreserveFields  []string  // Never redact these fields

    // Pattern customization
    CustomFieldPatterns   map[string][]string
    CustomContentPatterns []ContentPattern

    // Context rules
    ContextRules []ContextRule
    EnableContextAnalysis bool

    // Redaction options
    RedactionStrategy RedactionStrategy  // Mask, Hash, Remove, Replace
    MaskChar          rune              // Character for masking (default: *)
    MaskLength        MaskLengthStrategy // Full, Partial, Preserve

    // Performance tuning
    MaxDepth          int   // Max nesting level to traverse
    SamplingRate      float64  // For high-volume scenarios (0.0-1.0)

    // Presidio integration (UI mode)
    PresidioURL       string
    PresidioTimeout   time.Duration
    PresidioThreshold float32  // Confidence threshold (0.0-1.0)
    FallbackToLocal   bool     // Use local detection if Presidio fails
}

type SanitizerMode int
const (
    ModeLogger SanitizerMode = iota  // Fast, pattern-based
    ModeUI                            // Precise, Presidio-enhanced
)

type RedactionStrategy int
const (
    StrategyMask RedactionStrategy = iota  // "***"
    StrategyHash                           // SHA256 hash
    StrategyRemove                         // Remove field
    StrategyReplace                        // "[REDACTED]"
    StrategyPartial                        // "j***@example.com"
)

type MaskLengthStrategy int
const (
    MaskFull MaskLengthStrategy = iota    // Replace entire value
    MaskPartial                           // Keep first/last chars
    MaskPreserve                          // Preserve length
)
```

### 5. Logger Mode (Zap Integration)

**Purpose**: High-performance PII sanitization for structured logging.

**Implementation Approach**:
- Use `zapcore.ObjectMarshaler` interface
- Avoid reflection for performance
- Pre-compile all regex patterns
- Use type-specific sanitizers

**Usage Example**:
```go
// Integration with Zap
type SanitizedUser struct {
    ID        string
    Email     string
    Name      string
    Phone     string
    OrderID   string
}

func (u SanitizedUser) MarshalLogObject(enc zapcore.ObjectEncoder) error {
    sanitizer := pii.NewSanitizer(pii.ModeLogger)

    enc.AddString("id", sanitizer.SanitizeField("id", u.ID))
    enc.AddString("email", sanitizer.SanitizeField("email", u.Email))
    enc.AddString("name", sanitizer.SanitizeField("name", u.Name))
    enc.AddString("phone", sanitizer.SanitizeField("phone", u.Phone))
    enc.AddString("orderId", sanitizer.SanitizeField("orderId", u.OrderID))

    return nil
}

// Or use automatic sanitization
logger.Info("user action",
    zap.Object("user", pii.Sanitize(user)))
```

**Generic Sanitizer for Arbitrary Structs**:
```go
// For cases where you can't control the struct definition
func (s *Sanitizer) SanitizeStruct(v interface{}) map[string]interface{} {
    // Use reflection sparingly, cache type information
    // Walk struct fields and apply sanitization rules
}

// Usage
logger.Info("event", zap.Any("data", sanitizer.SanitizeStruct(arbitraryData)))
```

### 6. UI Mode (Presidio Integration)

**Purpose**: High-precision PII detection for data displayed to users.

**Implementation**:
- HTTP client for Presidio REST API
- Fallback to local detection if Presidio unavailable
- Batch processing for efficiency
- Caching for repeated patterns

**Presidio API Integration**:
```go
type PresidioClient struct {
    analyzerURL    string
    anonymizerURL  string
    httpClient     *http.Client
    cache          *lru.Cache
}

type AnalyzeRequest struct {
    Text     string   `json:"text"`
    Language string   `json:"language"`
    Entities []string `json:"score_threshold,omitempty"`
}

type AnalyzeResponse struct {
    Results []struct {
        EntityType string  `json:"entity_type"`
        Start      int     `json:"start"`
        End        int     `json:"end"`
        Score      float32 `json:"score"`
    } `json:"results"`
}

func (p *PresidioClient) AnalyzeText(ctx context.Context, text string) ([]PIIEntity, error) {
    // Call Presidio analyzer
    // Apply threshold filtering
    // Return detected entities
}

func (p *PresidioClient) AnonymizeText(ctx context.Context, text string, entities []PIIEntity) (string, error) {
    // Call Presidio anonymizer
    // Apply configured redaction strategy
    // Return sanitized text
}
```

**Hybrid Approach**:
```go
func (s *Sanitizer) SanitizeForUI(ctx context.Context, data interface{}) (interface{}, error) {
    if s.mode != ModeUI {
        return nil, errors.New("sanitizer not in UI mode")
    }

    // Step 1: Local detection (fast, high-confidence cases)
    localResults := s.detectLocal(data)

    // Step 2: For uncertain cases, call Presidio
    uncertainFields := s.findUncertainFields(data, localResults)
    if len(uncertainFields) > 0 && s.presidio != nil {
        presidioResults := s.presidio.AnalyzeBatch(ctx, uncertainFields)
        localResults = merge(localResults, presidioResults)
    }

    // Step 3: Apply redaction
    return s.applyRedaction(data, localResults)
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)

**Deliverables**:
1. Project structure and build setup
2. Configuration system
3. Field name detector with default patterns
4. Content detector with regex patterns
5. Basic redaction strategies (mask, replace, remove)
6. Comprehensive unit tests

**Files**:
- `sanitizer.go` - Main sanitizer interface
- `config.go` - Configuration structures
- `detector_field.go` - Field name detection
- `detector_content.go` - Content pattern matching
- `redactor.go` - Redaction strategies
- `patterns.go` - Default PII patterns

### Phase 2: Context Analysis (Week 3)

**Deliverables**:
1. Context analyzer implementation
2. Context rules engine
3. False positive reduction logic
4. Path tracking for nested structures
5. Integration tests with complex nested data

**Files**:
- `context.go` - Context analysis
- `context_rules.go` - Context rule definitions
- `traversal.go` - Recursive data structure traversal

### Phase 3: Logger Mode (Week 4)

**Deliverables**:
1. Zap integration via `zapcore.ObjectMarshaler`
2. Performance optimizations
3. Reflection-based generic sanitizer (with caching)
4. Benchmarks comparing different approaches
5. Example implementations

**Files**:
- `logger.go` - Logger mode implementation
- `zap.go` - Zap-specific integration
- `reflect.go` - Reflection-based sanitizer (cached)
- `examples/zap/` - Example usage

**Performance Targets**:
- < 5% overhead for pre-defined types using MarshalLogObject
- < 20% overhead for reflection-based generic sanitizer
- Zero allocations for common cases

### Phase 4: UI Mode & Presidio Integration (Week 5)

**Deliverables**:
1. Presidio HTTP client
2. Analyzer and anonymizer API integration
3. Fallback mechanisms
4. Batch processing for efficiency
5. Response caching (LRU cache)
6. Docker Compose setup for local Presidio

**Files**:
- `presidio.go` - Presidio client
- `ui_mode.go` - UI mode implementation
- `cache.go` - Caching layer
- `docker-compose.yml` - Presidio containers

### Phase 5: Advanced Features (Week 6)

**Deliverables**:
1. Custom pattern registration
2. Plugin system for custom detectors
3. Metrics and observability (detection counts, redaction stats)
4. Performance monitoring hooks
5. Partial redaction strategies (e.g., "j***@example.com")

**Files**:
- `plugins.go` - Plugin interface
- `metrics.go` - Metrics collection
- `strategies.go` - Advanced redaction strategies

### Phase 6: Documentation & Examples (Week 7)

**Deliverables**:
1. Comprehensive README
2. API documentation (GoDoc)
3. Usage examples for common scenarios
4. Migration guide from other libraries
5. Performance tuning guide
6. Security best practices

**Files**:
- `README.md`
- `docs/` directory
- `examples/` directory

## API Design

### Core API

```go
package sanitizer

// NewSanitizer creates a new PII sanitizer with the given configuration
func New(config Config) (*Sanitizer, error)

// NewDefaultLogger returns a sanitizer configured for logging
func NewDefaultLogger() *Sanitizer

// NewDefaultUI returns a sanitizer configured for UI with Presidio
func NewDefaultUI(presidioURL string) *Sanitizer

// Sanitizer is the main PII sanitization engine
type Sanitizer struct {
    config          Config
    fieldDetector   *FieldDetector
    contentDetector *ContentDetector
    contextAnalyzer *ContextAnalyzer
    presidio        *PresidioClient
}

// SanitizeField sanitizes a single field value
func (s *Sanitizer) SanitizeField(fieldName, value string) string

// SanitizeStruct sanitizes a struct, returns sanitized map
func (s *Sanitizer) SanitizeStruct(v interface{}) map[string]interface{}

// SanitizeMap sanitizes a map
func (s *Sanitizer) SanitizeMap(m map[string]interface{}) map[string]interface{}

// SanitizeJSON sanitizes JSON data
func (s *Sanitizer) SanitizeJSON(data []byte) ([]byte, error)

// SanitizeWithContext sanitizes with explicit context
func (s *Sanitizer) SanitizeWithContext(ctx Context, v interface{}) interface{}

// DetectOnly returns detected PII without redaction
func (s *Sanitizer) DetectOnly(v interface{}) []Detection

type Detection struct {
    Path       []string  // Field path
    FieldName  string
    Value      string
    PIIType    string    // email, ssn, phone, etc.
    Confidence float32   // 0.0-1.0
    Source     string    // field_name, content, presidio
}
```

### Configuration Helpers

```go
// WithRedactFields adds fields to explicit redact list
func (c *Config) WithRedactFields(fields ...string) *Config

// WithPreserveFields adds fields to explicit preserve list
func (c *Config) WithPreserveFields(fields ...string) *Config

// WithCustomPattern adds a custom field pattern
func (c *Config) WithCustomPattern(piiType string, patterns []string) *Config

// WithContextRule adds a context rule
func (c *Config) WithContextRule(rule ContextRule) *Config

// WithRedactionStrategy sets the redaction strategy
func (c *Config) WithRedactionStrategy(strategy RedactionStrategy) *Config
```

### Zap Integration

```go
package sanitizer

import "go.uber.org/zap/zapcore"

// ZapField wraps a value and implements zapcore.ObjectMarshaler
func (s *Sanitizer) ZapField(v interface{}) zapcore.ObjectMarshaler

// ZapSanitizer returns a zap encoder wrapper
func (s *Sanitizer) ZapEncoder(enc zapcore.Encoder) zapcore.Encoder

// Usage:
// logger.Info("user event", sanitizer.ZapField(user))
```

## Testing Strategy

### Unit Tests
- Test each detector independently
- Test all regex patterns with positive and negative cases
- Test context rules with various scenarios
- Test all redaction strategies
- Test configuration parsing and validation

### Integration Tests
- Test with complex nested structures
- Test with various data types (JSON, structs, maps)
- Test Presidio integration (using mock server)
- Test Zap integration end-to-end
- Test performance with realistic data volumes

### Benchmark Tests
```go
BenchmarkSanitizeField
BenchmarkSanitizeStruct_Simple
BenchmarkSanitizeStruct_Nested
BenchmarkSanitizeStruct_DeepNesting
BenchmarkSanitizeMap
BenchmarkSanitizeJSON
BenchmarkZapIntegration
BenchmarkPresidioIntegration
```

### Performance Goals
- Logger mode: < 100 μs for typical struct (10 fields)
- UI mode (without Presidio): < 500 μs for typical struct
- UI mode (with Presidio): < 100ms for typical struct (network dependent)
- Memory: < 1KB allocation per sanitization operation

## Security Considerations

1. **No Logging of PII**: Ensure sanitizer itself doesn't log raw PII
2. **Memory Safety**: Clear sensitive data from memory after use
3. **Regex DoS**: Protect against regex denial-of-service with timeouts
4. **Presidio TLS**: Enforce TLS for Presidio communication
5. **Configuration Validation**: Validate all configuration to prevent bypass
6. **Default-Secure**: Default configuration should be conservative (over-redact rather than under-redact)

## Dependencies

### Required
- Go 1.21+ (for native error wrapping, generics)
- `go.uber.org/zap` - Logging integration
- Standard library (regexp, encoding/json, net/http)

### Optional
- LRU cache implementation (e.g., `github.com/hashicorp/golang-lru`)
- Testing utilities (e.g., `github.com/stretchr/testify`)

### External Services
- Microsoft Presidio (Docker containers) - Optional, for UI mode

## Deployment Considerations

### For Logger Mode
- No external dependencies
- Can be embedded directly in applications
- Minimal configuration required

### For UI Mode
- Requires Presidio deployment (Docker Compose provided)
- Presidio containers:
  ```yaml
  services:
    presidio-analyzer:
      image: mcr.microsoft.com/presidio-analyzer:latest
      ports:
        - "5001:3000"

    presidio-anonymizer:
      image: mcr.microsoft.com/presidio-anonymizer:latest
      ports:
        - "5002:3000"
  ```
- Network access to Presidio required
- Consider caching and batching for performance

## Example Usage Scenarios

### Scenario 1: Zap Logger Integration

```go
import (
    "go.uber.org/zap"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

// Initialize sanitizer
s := sanitizer.NewDefaultLogger()

// Configure explicit rules
s.Config().
    WithRedactFields("internal_id", "secret_token").
    WithPreserveFields("order_id", "product_name")

// Use with custom types
type User struct {
    Email     string
    FirstName string
    LastName  string
    OrderID   string
}

func (u User) MarshalLogObject(enc zapcore.ObjectEncoder) error {
    enc.AddString("email", s.SanitizeField("email", u.Email))
    enc.AddString("firstName", s.SanitizeField("firstName", u.FirstName))
    enc.AddString("lastName", s.SanitizeField("lastName", u.LastName))
    enc.AddString("orderId", s.SanitizeField("orderId", u.OrderID))
    return nil
}

// Or use generic sanitizer for arbitrary data
logger.Info("request received",
    zap.Any("payload", s.SanitizeStruct(requestData)))
```

### Scenario 2: UI Data Sanitization

```go
import (
    "context"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

// Initialize with Presidio
s := sanitizer.NewDefaultUI("http://localhost:5001")
s.Config().WithRedactionStrategy(sanitizer.StrategyPartial)

// Sanitize data before sending to frontend
func (h *Handler) GetUserProfile(w http.ResponseWriter, r *http.Request) {
    user := h.userService.GetUser(r.Context(), userID)

    // High-precision sanitization with Presidio
    sanitized, err := s.SanitizeForUI(r.Context(), user)
    if err != nil {
        // Fallback to local detection
        sanitized = s.SanitizeStruct(user)
    }

    json.NewEncoder(w).Encode(sanitized)
}
```

### Scenario 3: Custom Patterns and Rules

```go
// Add custom patterns
s.Config().
    WithCustomPattern("employee_id", []string{"emp_id", "employee_num", "staff_id"}).
    WithCustomPattern("internal_code", []string{"internal_.*", "legacy_.*"})

// Add context rules
s.Config().WithContextRule(sanitizer.ContextRule{
    Field: "title",  // Don't redact "title" unless in user context
    ParentContext: []string{"user", "employee", "customer"},
})

// Add custom content pattern
customPattern := sanitizer.ContentPattern{
    Name:    "custom_id",
    Pattern: regexp.MustCompile(`CUST-\d{8}`),
}
s.Config().CustomContentPatterns = append(
    s.Config().CustomContentPatterns,
    customPattern,
)
```

## Metrics and Observability

```go
type Metrics struct {
    FieldsProcessed   int64
    FieldsRedacted    int64
    DetectionsByType  map[string]int64  // email: 100, ssn: 50, etc.
    PresidioCalls     int64
    PresidioErrors    int64
    CacheHits         int64
    CacheMisses       int64
    ProcessingTimeNs  int64
}

// GetMetrics returns current metrics
func (s *Sanitizer) GetMetrics() Metrics

// ResetMetrics resets all metrics
func (s *Sanitizer) ResetMetrics()

// WithMetricsCallback sets a callback for metrics reporting
func (c *Config) WithMetricsCallback(callback func(Metrics))
```

## Future Enhancements

1. **Image PII Detection**: Integrate Presidio image-redactor for PII in images
2. **Multi-Language Support**: Extend Presidio integration for non-English text
3. **ML Model Integration**: Custom ML models for domain-specific PII
4. **Database Integration**: Direct integration with database query results
5. **gRPC Integration**: Support for gRPC logging middleware
6. **OpenTelemetry**: Integration with OpenTelemetry for distributed tracing
7. **Cloud Provider Integrations**: AWS Macie, Google DLP API as alternatives to Presidio
8. **Audit Logging**: Track what was redacted and why for compliance

## Success Metrics

1. **Performance**:
   - Logger mode: < 100 μs per struct
   - UI mode: < 100ms per API call (including Presidio)

2. **Accuracy**:
   - Logger mode: > 95% detection rate, < 5% false positive rate
   - UI mode: > 99% detection rate, < 1% false positive rate

3. **Adoption**:
   - Easy integration with existing codebases
   - < 10 lines of code for basic integration
   - Clear documentation and examples

4. **Reliability**:
   - Graceful degradation when Presidio unavailable
   - No crashes on malformed input
   - Memory-safe with no leaks

## Conclusion

This PII sanitizer will provide a production-ready, flexible solution for handling sensitive data in Go applications. The dual-mode approach balances performance (logger mode) with precision (UI mode), while the context-aware detection minimizes false positives. The modular design allows for easy customization and extension to meet specific organizational needs.

The phased implementation approach ensures that core functionality is stable before adding advanced features, and the comprehensive testing strategy ensures reliability and performance meet production requirements.
