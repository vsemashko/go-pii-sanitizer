# Critical Review of PII Sanitizer Plan

## Research Findings Summary

### Popular Go Logging Libraries (HIGH ADOPTION)

The Go logging ecosystem is dominated by three main libraries:

1. **uber-go/zap** - ~23,800 stars ⭐️⭐️⭐️
   - Most popular structured logging library
   - High performance, minimal allocations
   - `zapcore.ObjectMarshaler` interface for custom field marshaling

2. **rs/zerolog** - ~11,900 stars ⭐️⭐️
   - Zero-allocation JSON logger
   - Fastest performance in benchmarks
   - Chainable API design

3. **log/slog** - Standard library (Go 1.21+) ⭐️⭐️⭐️
   - Built into Go standard library
   - `slog.LogValuer` interface with **zero performance impact**
   - Becoming the standard approach

### Existing PII Sanitization Libraries (LOW ADOPTION)

All Go-specific PII libraries have extremely low adoption:

- `cockroachdb/redact` - 36 stars
- `ln80/pii` - unknown (very low)
- `AngusGMorrison/logfusc` - unknown (very low)
- `m-mizutani/masq` - unknown (very low)

**Implication**: There's a clear gap in the market. No well-established PII sanitization solution exists for Go.

### Regional Context

Target regions: Singapore, Malaysia, UAE, Thailand, Hong Kong (NOT United States)

Each region has specific national ID formats and regulations:
- **Singapore**: NRIC (9 chars), strict PDPA regulations
- **Malaysia**: MyKad (12 digits, format: YYMMDD-BP-###G)
- **UAE**: Emirates ID (15 digits, format: 784-YYYY-XXXXXXX-X)
- **Thailand**: National ID (13 digits)
- **Hong Kong**: HKID (1-2 letters + 6 digits + check digit)

## Critical Weaknesses in Current Plan

### 1. **Over-Engineering & Complexity** 🔴 CRITICAL

**Issues:**
- 7-week implementation timeline for what could be 2-3 weeks
- Dual-mode architecture adds unnecessary complexity upfront
- 6 phases with granular breakdown - too much planning, not enough iteration
- Plugin system (Phase 5) is speculative - YAGNI violation
- Advanced redaction strategies may not be needed initially

**Impact:**
- Delays time-to-value
- Increases maintenance burden
- Higher risk of abandonment before completion
- More code = more bugs

**Recommendation:**
- Start with MVP: Single mode, basic patterns, zap/slog integration
- **Build → Measure → Learn** approach
- Add complexity only when needed

### 2. **Wrong Geographic Focus** 🔴 CRITICAL

**Issues:**
- All patterns are US-centric (SSN, US phone formats, ZIP codes)
- No patterns for NRIC, MyKad, Emirates ID, HKID, Thai ID
- Credit card validation is global but mentioned in US context
- Tax ID patterns are US-specific (TIN)

**Impact:**
- Solution won't work for target markets (SG, MY, AE, TH, HK)
- Wasted implementation effort on irrelevant patterns
- Missing critical regional compliance requirements (PDPA)

**Recommendation:**
- Remove ALL US-specific patterns
- Implement Asia-Pacific and Middle East patterns
- Research PDPA, GDPR-like regulations in target countries

### 3. **Presidio Integration Complexity** 🟡 MODERATE

**Issues:**
- Presidio requires Docker deployment, adds operational overhead
- REST API calls add latency (~100ms target includes network)
- Presidio is trained primarily on English/US data
- Dual-mode approach splits effort and testing

**Questions:**
- Do you REALLY need ML-powered detection for UI data?
- Can pattern-matching + context analysis achieve 95%+ accuracy?
- What's the actual false-positive tolerance for UI vs logs?

**Recommendation:**
- **Phase 1**: Skip Presidio entirely, use pattern + context detection
- **Phase 2**: If accuracy is insufficient, add Presidio as optional enhancement
- Consider: Presidio might not be well-trained for SG/MY/AE/TH/HK names and addresses

### 4. **Context Analysis Over-Complexity** 🟡 MODERATE

**Issues:**
- Context rules system is sophisticated but unproven
- Requires maintaining complex rule sets
- Harder to debug when it misclassifies
- Performance implications of tree traversal

**Example from plan:**
```go
nameRule := ContextRule{
    Field: "name",
    RequiredContext: []string{"email", "phone", "address", "ssn", "surname"},
    ParentContext: []string{"user", "customer", "patient", "employee", "person"},
}
```

This is clever but complex. Alternative: **Struct tags** or **allowlist/denylist** is simpler.

**Recommendation:**
- Start with simple allowlist/denylist approach
- Add struct tag support: `json:"name" pii:"conditional"` or `pii:"always"`
- Only add context rules if false positives are problematic in practice

### 5. **Missing Integration with Popular Libraries** 🟡 MODERATE

**Issues:**
- Plan mentions zap integration but not zerolog (11.9k stars)
- Doesn't leverage slog's `LogValuer` interface (stdlib, zero overhead)
- `zapcore.ObjectMarshaler` requires users to modify their types

**Recommendation:**
- Provide middleware/wrappers for all three: zap, zerolog, slog
- **slog should be primary** (stdlib, zero performance impact, modern)
- Provide encoder wrappers so users don't modify existing structs

### 6. **Reflection-Based Approach Concerns** 🟡 MODERATE

**Issues:**
- Plan acknowledges reflection has 2.5x performance penalty (4ms→10ms)
- Then proposes using it with caching as "generic sanitizer"
- Caching helps but doesn't eliminate overhead

**Reality:**
- Production logs are high-volume
- 2.5x overhead on critical path is often unacceptable
- Caching can have memory implications at scale

**Recommendation:**
- Avoid reflection-based approaches for logger mode
- For UI mode (lower volume), reflection is acceptable
- Encourage users to implement `slog.LogValuer` or `zapcore.ObjectMarshaler`
- Provide code generation tool as alternative to reflection

### 7. **Configuration Overload** 🟢 MINOR

**Issues:**
- Configuration struct has 15+ options
- Makes API intimidating for new users
- Many options may never be used

**Recommendation:**
- Provide sensible defaults
- Make 90% use case work with zero configuration
- Use builder pattern or functional options for advanced config

### 8. **Missing Struct Tag Support** 🟡 MODERATE

**Issues:**
- No mention of struct tags for field-level control
- Forces users to rely on naming patterns or explicit config

**Better approach:**
```go
type User struct {
    Email     string `json:"email" pii:"redact"`
    FirstName string `json:"firstName" pii:"conditional"` // context-dependent
    OrderID   string `json:"orderId" pii:"preserve"`
    Internal  string `json:"-" pii:"redact"`  // always redact
}
```

This is explicit, type-safe, and self-documenting.

### 9. **Unclear Value Proposition for UI Mode** 🟡 MODERATE

**Questions:**
- Why does UI data need "high precision" sanitization?
- If data is being sent to UI, why not sanitize at the backend before storing?
- Are you sanitizing for display (partial masking) or for compliance?

**Scenarios:**
1. **Display masking** (e.g., `**** **** **** 1234`): Don't need Presidio, simple pattern matching
2. **Compliance** (e.g., PDPA): Should sanitize before storing, not on display
3. **Audit logs** (e.g., "User viewed sensitive data"): Need detection, not anonymization

**Recommendation:**
- Clarify the actual UI use case
- Consider if "UI mode" is really just "non-logging sanitization"
- Maybe: Single library with configurable redaction strategies (full/partial/hash)

## Simplification Opportunities

### ✅ Simplified Architecture

```
MVP Approach:
┌─────────────────────────────────────────┐
│         PII Sanitizer Core              │
├─────────────────────────────────────────┤
│  1. Pattern Matcher (field + content)  │
│  2. Redaction Engine (mask/remove)     │
│  3. Configuration (allowlist/denylist) │
└─────────────────────────────────────────┘
              │
    ┌─────────┴─────────┐
    ▼                   ▼
┌─────────┐      ┌──────────────┐
│  slog   │      │  zap/zerolog │
│ wrapper │      │   wrapper    │
└─────────┘      └──────────────┘
```

**Phase 2 (if needed):**
- Add context analysis
- Add Presidio integration
- Add struct tag support

### ✅ Simplified Implementation Timeline

**Week 1: Core + Patterns**
- Pattern matching for APAC/ME regions (SG/MY/AE/TH/HK)
- Field name detection
- Content detection (email, phone, IDs, credit card)
- Basic redaction (mask, remove)
- Configuration (explicit lists)

**Week 2: Logger Integration**
- slog.LogValuer wrapper (primary)
- zapcore.ObjectMarshaler helper
- zerolog hook
- JSON sanitizer (for arbitrary maps/structs)

**Week 3: Testing + Docs**
- Unit tests
- Benchmarks
- Examples
- Documentation
- Performance tuning

**Week 4: Iteration**
- Add struct tags if needed
- Add partial masking if needed
- Add context rules if false positives are high
- Consider Presidio if accuracy insufficient

### ✅ Recommended API (Simplified)

```go
package sanitizer

// Simple constructor with defaults
func New() *Sanitizer

// Fluent configuration
func (s *Sanitizer) WithRedactFields(fields ...string) *Sanitizer
func (s *Sanitizer) WithPreserveFields(fields ...string) *Sanitizer
func (s *Sanitizer) WithRegion(region Region) *Sanitizer // SG, MY, AE, TH, HK

// Primary interface - works with slog
type PII[T any] struct { Value T }
func (p PII[T]) LogValue() slog.Value // implements slog.LogValuer

// Usage with slog
slog.Info("user action",
    "user", sanitizer.Wrap(user),
    "email", sanitizer.WrapField("email", email))

// Helper for zap
func (s *Sanitizer) ZapField(key string, value interface{}) zapcore.Field

// Generic sanitization for UI/API
func (s *Sanitizer) SanitizeJSON(data []byte) ([]byte, error)
func (s *Sanitizer) SanitizeMap(m map[string]interface{}) map[string]interface{}
```

### ✅ Struct Tags (Opt-in Enhancement)

```go
// Only if reflection overhead is acceptable for the use case
type User struct {
    Email    string `pii:"redact"`
    Name     string `pii:"conditional,context=user"`
    OrderID  string `pii:"preserve"`
}

func (s *Sanitizer) SanitizeStruct(v interface{}) map[string]interface{}
```

## Regional Patterns Implementation

### Singapore (NRIC)
```go
// Format: X1234567A (letter + 7 digits + checksum letter)
// Also: FIN (Foreign Identification Number)
patterns := map[string]string{
    "nric": `^[STFGM]\d{7}[A-Z]$`,
    "phone": `^\+65[689]\d{7}$`,
}
```

### Malaysia (MyKad)
```go
// Format: YYMMDD-BP-###G (12 digits)
patterns := map[string]string{
    "mykad": `^\d{6}-\d{2}-\d{4}$`,
    "phone": `^(\+?6?01)[02-46-9]-*\d{7}$|^(\+?6?01)[1]-*\d{8}$`,
}
```

### UAE (Emirates ID)
```go
// Format: 784-YYYY-XXXXXXX-X (15 digits)
patterns := map[string]string{
    "emirates_id": `^784-\d{4}-\d{7}-\d{1}$`,
    "phone": `^(\+971|00971|0)(2|3|4|6|7|9|50|51|52|55|56)\d{7}$`,
}
```

### Thailand (National ID)
```go
// Format: 13 digits
patterns := map[string]string{
    "thai_id": `^\d{13}$`,  // Can add check digit validation
    "phone": `^\+66[0-9]{8,9}$`,
}
```

### Hong Kong (HKID)
```go
// Format: X123456(A) - 1-2 letters + 6 digits + check digit
patterns := map[string]string{
    "hkid": `^[A-Z]{1,2}\d{6}[A0-9]$`,
    "phone": `^\+852[5-9]\d{7}$`,
}
```

## Recommendations Summary

### 🎯 TOP PRIORITY

1. **Start Simple**: 3-week MVP, not 7-week full build
2. **Fix Regional Patterns**: Remove US patterns, add SG/MY/AE/TH/HK
3. **slog First**: Leverage stdlib with zero-overhead `LogValuer` interface
4. **Skip Presidio for MVP**: Pattern matching + explicit config is likely sufficient

### 🔧 ARCHITECTURE

5. **Single Mode Initially**: Don't split logger/UI modes
6. **Avoid Reflection**: Encourage explicit interfaces (LogValuer, ObjectMarshaler)
7. **Struct Tags as V2**: Only add if users request it
8. **Simple Config**: Default-safe, minimal required configuration

### 📊 VALIDATION

9. **Build for Real Use Cases**: What are the actual top 5 PII types you need to catch?
10. **Measure False Positives**: Track in production, iterate based on data
11. **Performance Benchmarks**: Ensure < 5% overhead for logger use case

### 🚀 ROLLOUT

12. **Week 1-3**: MVP with core patterns and slog/zap integration
13. **Week 4**: Production pilot with real data
14. **Week 5+**: Iterate based on feedback - add context rules, Presidio, etc. only if needed

## Questions to Clarify

1. **UI Mode Use Case**: What exactly are you sanitizing for display? Partial masking? Full redaction?

2. **Top PII Types**: What are the top 10 PII field types you encounter? Helps prioritize patterns.

3. **False Positive Tolerance**:
   - Logger mode: Can you tolerate 5% false positives? 10%?
   - UI mode: How critical is precision vs recall?

4. **Volume**:
   - Logger mode: How many log entries per second?
   - UI mode: How many API calls per second?

5. **Compliance**: Are you trying to meet PDPA requirements? GDPR? Other?

6. **Existing Code**: Do you control the structs being logged, or are they from third-party libraries?

## Conclusion

The original plan is **comprehensive but over-engineered**. The Go ecosystem lacks a good PII sanitization library, so there's real value here, but:

- Start with 20% of the features that solve 80% of the problems
- Focus on Asia-Pacific + Middle East patterns (not US)
- Leverage stdlib (slog) for zero-overhead integration
- Iterate based on real usage, not speculation

**Suggested approach**: Build a lean, focused library that does pattern-matching and field-name detection really well, with seamless slog/zap integration. Add complexity (context rules, Presidio, plugins) only when real-world usage demonstrates the need.
