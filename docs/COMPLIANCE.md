# Compliance Guide

This document provides guidance on using the PII sanitizer to help meet data protection and privacy compliance requirements in Singapore, Malaysia, UAE, Thailand, and Hong Kong.

## ⚠️ Important Disclaimer

**This library is a technical tool to assist with PII redaction. It does NOT guarantee compliance with any regulation.**

- Legal compliance requires organizational policies, procedures, and governance
- This tool should be part of a broader data protection strategy
- Consult with legal counsel for compliance advice
- Regular audits and reviews are essential

---

## Table of Contents

- [Supported Regions](#supported-regions)
- [Regional Compliance](#regional-compliance)
  - [Singapore PDPA](#singapore-pdpa-)
  - [Malaysia PDPA](#malaysia-pdpa-)
  - [UAE Data Protection](#uae-data-protection-)
  - [Thailand PDPA](#thailand-pdpa-)
  - [Hong Kong PDPO](#hong-kong-pdpo-)
- [Common Requirements](#common-requirements)
- [Implementation Guide](#implementation-guide)
- [Audit and Monitoring](#audit-and-monitoring)
- [Limitations](#limitations)

---

## Supported Regions

| Region | Regulation | Sanitizer Support |
|--------|-----------|-------------------|
| 🇸🇬 Singapore | Personal Data Protection Act 2012 (PDPA) | ✅ Full |
| 🇲🇾 Malaysia | Personal Data Protection Act 2010 (PDPA) | ✅ Full |
| 🇦🇪 UAE | Federal Decree-Law No. 45/2021 | ✅ Full |
| 🇹🇭 Thailand | Personal Data Protection Act B.E. 2562 (2019) | ✅ Full |
| 🇭🇰 Hong Kong | Personal Data (Privacy) Ordinance (PDPO) | ✅ Full |

---

## Regional Compliance

### Singapore PDPA 🇸🇬

**Regulation:** Personal Data Protection Act 2012

**Effective:** July 2, 2014

**Key Principles:**
1. Consent Obligation
2. Purpose Limitation Obligation
3. Notification Obligation
4. Access and Correction Obligation
5. Accuracy Obligation
6. Protection Obligation ← **Sanitizer helps here**
7. Retention Limitation Obligation
8. Transfer Limitation Obligation
9. Openness Obligation
10. Data Breach Notification Obligation

#### How the Sanitizer Helps

**Protection Obligation (Section 24):**
> Organizations must protect personal data in their possession or control by making reasonable security arrangements to prevent unauthorized access, collection, use, disclosure, copying, modification, disposal, or similar risks.

**Implementation:**
```go
// Singapore-focused sanitizer
sgSanitizer := NewForRegion(Singapore)

// Sanitize before logging
logger.Info("user action",
    zap.Object("user", sgSanitizer.ZapObject(userData)))

// Sanitize before storing in non-production environments
devData := sgSanitizer.SanitizeMap(productionData)
```

#### Covered PII Types

| PII Type | PDPA Relevance | Detection |
|----------|----------------|-----------|
| NRIC | High sensitivity under PDPA | ✅ Pattern matching |
| Email | Personal data | ✅ Field name + content |
| Phone | Personal data | ✅ Regional format |
| Address | Personal data | ✅ Field name matching |
| Bank account | Financial data | ✅ Pattern matching |
| Full name | Personal data | ✅ Field name matching |

**Advisory Guidelines:**
- PDPA requires reasonable security arrangements
- Sanitization in logs helps prevent unauthorized disclosure
- Use in development/staging environments reduces risk
- Regular audits recommended (see [Audit and Monitoring](#audit-and-monitoring))

**References:**
- [PDPC Singapore](https://www.pdpc.gov.sg/)
- [Advisory Guidelines on Key Concepts in the PDPA](https://www.pdpc.gov.sg/-/media/Files/PDPC/PDF-Files/Advisory-Guidelines/Advisory-Guidelines-on-Key-Concepts-in-the-PDPA-2-July-2020.pdf)

---

### Malaysia PDPA 🇲🇾

**Regulation:** Personal Data Protection Act 2010

**Effective:** November 15, 2013

**Key Principles:**
1. General Principle
2. Notice and Choice Principle
3. Disclosure Principle
4. Security Principle ← **Sanitizer helps here**
5. Retention Principle
6. Data Integrity Principle
7. Access Principle

#### How the Sanitizer Helps

**Security Principle (Section 8):**
> A data user shall take practical steps to protect personal data from loss, misuse, modification, unauthorized or accidental access or disclosure, alteration or destruction.

**Implementation:**
```go
// Malaysia-focused sanitizer
mySanitizer := NewForRegion(Malaysia)

// Sanitize MyKad and other Malaysian PII
sanitized := mySanitizer.SanitizeMap(map[string]interface{}{
    "ic": "901230-14-5678",      // MyKad - REDACTED
    "name": "Ahmad bin Ali",      // Name - REDACTED
    "email": "ahmad@example.com", // Email - REDACTED
})
```

#### Covered PII Types

| PII Type | PDPA Relevance | Detection |
|----------|----------------|-----------|
| MyKad (IC) | National ID (sensitive) | ✅ Pattern `YYMMDD-PB-###` |
| Email | Personal data | ✅ Field name + content |
| Phone | Personal data | ✅ Regional format |
| Address | Personal data | ✅ Field name matching |
| Bank account | Financial data | ✅ Pattern matching |
| Full name | Personal data | ✅ Field name matching |

**Commissioner's Guidance:**
- Personal data must be protected against accidental loss, destruction, damage, unauthorized disclosure
- Apply security measures appropriate to sensitivity of data
- Sanitization in non-production environments recommended

**References:**
- [Department of Personal Data Protection Malaysia](http://www.pdp.gov.my/)
- [Personal Data Protection Standards](http://www.pdp.gov.my/index.php/en/perundangan-dan-kawal-selia-en/personal-data-protection-standards-en)

---

### UAE Data Protection 🇦🇪

**Regulation:** Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data

**Effective:** January 2, 2022

**Key Articles:**
- Article 3: Principles of Personal Data Processing
- Article 6: Security of Personal Data ← **Sanitizer helps here**
- Article 7: Breach Notification
- Article 9: Rights of Data Subject

#### How the Sanitizer Helps

**Article 6 - Security of Personal Data:**
> The Controller shall implement appropriate technical and organizational measures to protect Personal Data from unauthorized access, disclosure, alteration, or destruction.

**Implementation:**
```go
// UAE-focused sanitizer
uaeSanitizer := NewForRegion(UAE)

// Sanitize Emirates ID and IBAN
sanitized := uaeSanitizer.SanitizeMap(map[string]interface{}{
    "emiratesId": "784-2020-1234567-1", // Emirates ID - REDACTED
    "iban": "AE070331234567890123456",   // UAE IBAN - REDACTED
    "email": "user@example.ae",          // Email - REDACTED
})
```

#### Covered PII Types

| PII Type | Regulation Relevance | Detection |
|----------|---------------------|-----------|
| Emirates ID | National ID (Article 1) | ✅ Pattern `784-YYYY-XXXXXXX-D` |
| IBAN | Financial data | ✅ Pattern `AE` + 21 digits |
| Email | Personal data | ✅ Field name + content |
| Phone | Personal data | ✅ Regional format |
| Address | Personal data | ✅ Field name matching |
| Full name | Personal data | ✅ Field name matching |

**Regulatory Notes:**
- Emirates ID is considered sensitive personal data
- IBAN falls under financial data requiring enhanced protection
- Technical measures include encryption, access controls, and data minimization
- Sanitization supports data minimization in logs and non-production environments

**References:**
- [UAE Data Protection Law](https://u.ae/en/about-the-uae/digital-uae/data/data-protection)
- [TDRA Guidelines](https://tdra.gov.ae/)

---

### Thailand PDPA 🇹🇭

**Regulation:** Personal Data Protection Act B.E. 2562 (2019)

**Effective:** June 1, 2022

**Key Sections:**
- Section 37: Security Measures ← **Sanitizer helps here**
- Section 42: Notification of Data Breach
- Section 45: Rights of Data Subject

#### How the Sanitizer Helps

**Section 37 - Security Measures:**
> A data controller shall put in place appropriate security measures to prevent unauthorized or unlawful access to or disclosure, alteration, correction or destruction of personal data.

**Implementation:**
```go
// Thailand-focused sanitizer
thSanitizer := NewForRegion(Thailand)

// Sanitize Thai National ID and personal data
sanitized := thSanitizer.SanitizeMap(map[string]interface{}{
    "nationalId": "1-2345-67890-12-3",  // Thai National ID - REDACTED
    "name": "สมชาย",                     // Name - REDACTED
    "phone": "+66812345678",             // Phone - REDACTED
})
```

#### Covered PII Types

| PII Type | PDPA Relevance | Detection |
|----------|----------------|-----------|
| National ID (13 digits) | Sensitive data (Section 26) | ✅ Pattern `X-XXXX-XXXXX-XX-X` |
| Email | Personal data | ✅ Field name + content |
| Phone | Personal data | ✅ Regional format |
| Address | Personal data | ✅ Field name matching |
| Bank account | Financial data | ✅ Pattern matching |
| Full name | Personal data | ✅ Field name matching |

**PDPC Thailand Guidelines:**
- National ID cards are sensitive personal data requiring explicit consent
- Enhanced security measures required for sensitive data
- Data minimization principle applies - collect only necessary data
- Sanitization helps comply with data minimization in development environments

**References:**
- [Personal Data Protection Committee Thailand](https://www.pdpc.or.th/)
- [PDPA Guidelines](https://www.pdpc.or.th/en/law)

---

### Hong Kong PDPO 🇭🇰

**Regulation:** Personal Data (Privacy) Ordinance (Cap. 486)

**Effective:** December 20, 1996 (Amended 2021)

**Data Protection Principles:**
1. Purpose and Manner of Collection
2. Accuracy and Retention
3. Use of Personal Data
4. Security of Personal Data ← **Sanitizer helps here**
5. Openness
6. Access to Personal Data

#### How the Sanitizer Helps

**Data Protection Principle 4 - Security:**
> All practicable steps shall be taken to ensure that personal data is protected against unauthorized or accidental access, processing, erasure, loss or use.

**Implementation:**
```go
// Hong Kong-focused sanitizer
hkSanitizer := NewForRegion(HongKong)

// Sanitize HKID and personal data
sanitized := hkSanitizer.SanitizeMap(map[string]interface{}{
    "hkid": "A123456(7)",         // HKID - REDACTED
    "name": "陳大文",              // Name - REDACTED
    "email": "user@example.hk",   // Email - REDACTED
})
```

#### Covered PII Types

| PII Type | PDPO Relevance | Detection |
|----------|----------------|-----------|
| HKID | Identity document | ✅ Pattern `[A-Z]{1,2}######(#)` |
| Email | Personal data | ✅ Field name + content |
| Phone | Personal data | ✅ Regional format |
| Address | Personal data | ✅ Field name matching |
| Bank account | Financial data | ✅ Pattern matching |
| Full name | Personal data | ✅ Field name matching |

**Privacy Commissioner Guidance:**
- HKID numbers should be collected only when necessary
- Truncation or masking recommended when full HKID not required
- Security measures should match data sensitivity
- Regular security audits recommended

**References:**
- [Office of the Privacy Commissioner for Personal Data, Hong Kong](https://www.pcpd.org.hk/)
- [Guidance on HKID Numbers](https://www.pcpd.org.hk/english/resources_centre/publications/files/GN_HKID_e.pdf)

---

## Common Requirements

### Data Minimization

**Principle:** Collect and process only the minimum necessary personal data.

**How Sanitizer Helps:**
```go
// Production: Full data (necessary for business logic)
productionData := getUserData()

// Development: Sanitized data (minimized PII exposure)
devData := sanitizer.SanitizeMap(productionData)
saveToDevDatabase(devData)
```

**Applies to:**
- Development/staging environments
- Logs and monitoring
- Analytics and reporting
- Backups and archives

### Security Measures

**Principle:** Implement appropriate technical and organizational measures.

**How Sanitizer Helps:**
```go
// Logs: Sanitize PII before writing
logger.Info("user login",
    zap.Object("user", sanitizer.ZapObject(user)))

// Error messages: Don't expose PII
if err != nil {
    sanitizedCtx := sanitizer.SanitizeMap(context)
    logger.Error("operation failed",
        zap.Error(err),
        zap.Any("context", sanitizedCtx))
}

// Metrics: Sanitize labels
prometheus.Counter("user_action",
    sanitizer.SanitizeField("userId", userID))
```

### Purpose Limitation

**Principle:** Use personal data only for stated purposes.

**How Sanitizer Helps:**
- Use different sanitizer configs for different purposes
- Stricter sanitization for secondary uses (analytics, testing)

```go
// Primary purpose: User service (permissive)
userServiceSanitizer := New(NewDefaultConfig().
    WithPreserve("orderId", "productId"))

// Secondary purpose: Analytics (strict)
analyticsSanitizer := New(NewDefaultConfig().
    WithStrategy(StrategyHash). // Hash for correlation
    WithRedact("description", "notes", "memo"))
```

### Retention Limitation

**Principle:** Retain personal data no longer than necessary.

**How Sanitizer Helps:**
```go
// Before deletion: Sanitize for audit trail
auditLog := sanitizer.SanitizeMap(userData)
saveAuditLog(auditLog) // PII-free audit record

// Then delete original
deleteUser(userId)
```

---

## Implementation Guide

### 1. Identify PII in Your System

**Audit your data:**
```go
// Example: User profile
type User struct {
    ID          string  // ✅ Safe (business ID)
    Email       string  // ❌ PII
    FullName    string  // ❌ PII
    Phone       string  // ❌ PII
    NRIC        string  // ❌ Sensitive PII
    Address     Address // ❌ PII
    OrderIDs    []string // ✅ Safe (business IDs)
    CreatedAt   time.Time // ✅ Safe
}
```

### 2. Configure Sanitizers

**Different configs for different environments:**
```go
// Production logs: Permissive (business IDs preserved)
var prodLogSanitizer = New(NewDefaultConfig().
    WithPreserve("userId", "orderId", "transactionId", "sessionId").
    WithRegions(Singapore, Malaysia)) // Only relevant regions

// UI/API: Strict (minimal PII exposure)
var uiSanitizer = New(NewDefaultConfig().
    WithStrategy(StrategyFull).
    WithRedact("description", "notes", "memo"))

// Analytics: Hash (correlation without PII)
var analyticsSanitizer = New(NewDefaultConfig().
    WithStrategy(StrategyHash).
    WithRegions(Singapore)) // Only Singapore for analytics
```

### 3. Integrate with Logging

**Logger integration:**
```go
import (
    "go.uber.org/zap"
    "github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

var (
    logger = zap.NewProduction()
    s      = sanitizer.NewDefault()
)

func HandleUserAction(user User) {
    // Sanitize before logging
    logger.Info("user action",
        zap.Object("user", s.ZapObject(user)),
        zap.String("action", "login"))
}
```

### 4. Sanitize Development Data

**Database seeding:**
```go
func SeedDevDatabase() {
    prodData := fetchProductionData()

    // Sanitize before copying to dev
    devData := sanitizer.SanitizeMap(prodData)

    seedDatabase(devData)
}
```

### 5. Implement Access Controls

**Combine with authorization:**
```go
func GetUserProfile(ctx context.Context, userId string) (map[string]interface{}, error) {
    user := fetchUser(userId)

    // Admin: Full access
    if isAdmin(ctx) {
        return user, nil
    }

    // Regular user: Sanitized
    return sanitizer.SanitizeMap(user), nil
}
```

### 6. Monitor and Audit

**Metrics:**
```go
var sanitizationCounter = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "pii_sanitization_total",
        Help: "Total PII sanitization operations",
    },
    []string{"environment", "data_type"},
)

func SanitizeWithMetrics(data map[string]interface{}) map[string]interface{} {
    sanitizationCounter.WithLabelValues("production", "user").Inc()
    return sanitizer.SanitizeMap(data)
}
```

---

## Audit and Monitoring

### Compliance Checklist

- [ ] **Identify all PII** in your system
- [ ] **Configure appropriate regions** (only enable what you need)
- [ ] **Sanitize logs** before writing (use logger integrations)
- [ ] **Sanitize dev/staging data** (no production PII in non-prod)
- [ ] **Document PII handling** in privacy policy
- [ ] **Train developers** on PII handling
- [ ] **Regular audits** (quarterly recommended)
- [ ] **Monitor sanitization effectiveness** (metrics, alerts)
- [ ] **Test data breach scenarios** (ensure sanitization works)
- [ ] **Review and update patterns** (new PII types, regulations)

### Audit Queries

**Check for unsanitized PII in logs:**
```bash
# Search logs for email patterns
grep -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' application.log

# Search for phone numbers
grep -E '\+65[689]\d{7}' application.log

# Search for NRIC
grep -E '[STFGM]\d{7}[A-Z]' application.log
```

**Automated monitoring:**
```go
// Alert if PII detected in logs
func MonitorLogs(logLine string) {
    if containsEmail(logLine) ||
       containsPhone(logLine) ||
       containsNRIC(logLine) {
        alertSecurityTeam("Unsanitized PII detected in logs", logLine)
    }
}
```

### Regular Reviews

**Quarterly reviews:**
1. Review sanitization configurations
2. Check for new PII types in data model
3. Audit log files for unsanitized PII
4. Test sanitization with production-like data
5. Update patterns for new regulations
6. Review false positive/negative rates

---

## Limitations

### What the Sanitizer Does NOT Do

❌ **Does not replace legal compliance:**
- You still need privacy policies
- You still need user consent mechanisms
- You still need data processing agreements
- You still need incident response plans

❌ **Does not detect all PII:**
- Contextual PII (e.g., "John's email" without email present)
- Unstructured text (free-form essays, documents)
- Images, videos, audio files
- Binary data, encrypted data

❌ **Does not prevent all disclosure:**
- Data in backups (sanitize before backup)
- Data in databases (application-level protection needed)
- Data in memory dumps
- Data in network traffic (use TLS)

❌ **Does not guarantee accuracy:**
- False positives possible (safe data redacted)
- False negatives possible (PII missed)
- Regular testing and tuning required

### Recommended Complementary Measures

1. **Encryption at rest and in transit**
2. **Access controls and authentication**
3. **Regular security audits**
4. **Incident response procedures**
5. **Data classification and handling policies**
6. **Employee training on data protection**
7. **Vendor risk management**
8. **Privacy impact assessments**

---

## Support and Resources

### Official Documentation

- [Singapore PDPC](https://www.pdpc.gov.sg/)
- [Malaysia PDPA](http://www.pdp.gov.my/)
- [UAE Data Protection](https://u.ae/en/about-the-uae/digital-uae/data/data-protection)
- [Thailand PDPC](https://www.pdpc.or.th/)
- [Hong Kong PCPD](https://www.pcpd.org.hk/)

### Library Documentation

- [README.md](../README.md) - Getting started
- [PATTERNS.md](./PATTERNS.md) - Pattern reference
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance guide
- [Examples](../examples/) - Working code examples

### Getting Help

For compliance questions:
- **Legal:** Consult with qualified legal counsel
- **Technical:** Open an issue on GitHub
- **Security:** Email security contact (if disclosed in README)

---

## Disclaimer

**This documentation is for informational purposes only and does not constitute legal advice.**

The PII sanitizer library is provided "as is" without warranty. Users are solely responsible for:
- Ensuring compliance with applicable laws and regulations
- Testing the library with their specific use cases
- Implementing additional security and privacy measures as needed
- Consulting with legal counsel for compliance advice

Personal data protection laws are complex and vary by jurisdiction. Always seek professional legal advice for compliance matters.
