# PII Pattern Reference

This document provides a comprehensive reference of all PII patterns detected by the sanitizer.

## Table of Contents

- [Common Patterns](#common-patterns)
- [Regional Patterns](#regional-patterns)
  - [Singapore](#singapore--)
  - [Malaysia](#malaysia--)
  - [UAE](#uae--)
  - [Thailand](#thailand--)
  - [Hong Kong](#hong-kong--)
- [Custom Patterns](#custom-patterns)

## Common Patterns

These patterns are enabled for all regions and detect universal PII types.

### Legal Names (Priority 1)

**Field Names:**
- `fullName`, `full_name`, `legalName`, `legal_name`
- `firstName`, `first_name`, `lastName`, `last_name`
- `surname`, `givenName`, `given_name`
- `customerName`, `customer_name`, `userName`, `user_name`
- `displayName`, `display_name`, `realName`, `real_name`

**Example Matches:**
```json
{
  "fullName": "John Doe",           // REDACTED
  "firstName": "Jane",               // REDACTED
  "user_name": "Alice Smith"         // REDACTED
}
```

### Transaction Descriptions (Priority 2)

**Field Names:**
- `description`, `transactionDescription`, `transaction_description`
- `memo`, `narrative`, `reference`, `remarks`, `notes`
- `paymentReference`, `payment_reference`
- `transferDetails`, `transfer_details`, `transactionNotes`

**Example Matches:**
```json
{
  "description": "Payment to John Doe for services",  // REDACTED
  "memo": "Rent payment - Apartment 123",            // REDACTED
  "reference": "Invoice #12345 for Jane Smith"       // REDACTED
}
```

### Bank Account Numbers (Priority 3)

**Detection Method:** Field name matching ONLY (no content patterns)

**Field Names:**
- `accountNumber`, `account_number`, `bankAccount`, `bank_account`
- `iban`, `accountNo`, `account_no`
- `accountId`, `account_id`, `bankAccountNumber`

**Example Matches:**
```json
{
  "accountNumber": "1234567890",     // REDACTED (field name match)
  "iban": "AE070331234567890123456", // REDACTED (field name match)
  "bank_account": "123-456-789"      // REDACTED (field name match)
}
```

**⚠️ Important (v1.0 Change):**
- Bank accounts are detected **only via field name matching**
- Content patterns removed to prevent false positives on order IDs, transaction IDs, etc.
- If you need content-based detection, add custom patterns via `config.CustomContentPatterns`

### Email Addresses (Priority 4)

**Field Names:**
- `email`, `emailAddress`, `email_address`
- `userEmail`, `user_email`, `contactEmail`, `contact_email`
- `emailId`, `email_id`, `workEmail`, `personalEmail`

**Content Pattern:**
```regex
\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
```

**Example Matches:**
```json
{
  "email": "user@example.com",              // REDACTED
  "message": "Contact us at info@acme.com"  // Content: REDACTED
}
```

### Physical Addresses (Priority 5)

**Field Names:**
- `address`, `streetAddress`, `street_address`, `homeAddress`
- `street`, `street1`, `street2`, `addressLine1`, `addressLine2`
- `city`, `state`, `country`, `postalCode`, `postal_code`, `zipCode`, `zip_code`
- `location`, `residentialAddress`, `billingAddress`, `shippingAddress`

**Example Matches:**
```json
{
  "street": "123 Main Street",       // REDACTED
  "address": "Apartment 45B",        // REDACTED
  "postalCode": "123456"             // REDACTED
}
```

### Phone Numbers

**Field Names:**
- `phone`, `phoneNumber`, `phone_number`, `mobile`, `mobileNumber`
- `telephone`, `tel`, `contactNumber`, `contact_number`
- `cellphone`, `cell`, `workPhone`, `homePhone`

**Example Matches:**
```json
{
  "phone": "+6591234567",            // REDACTED
  "mobile": "0123456789"             // REDACTED
}
```

### Credit Card Numbers

**Content Pattern:**
```regex
\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,3}\b
```

**Validation:** Luhn algorithm (checksum validation)

**Field Names:**
- `creditCard`, `credit_card`, `cardNumber`, `card_number`
- `ccNumber`, `cc_number`, `pan`, `paymentCard`

**Example Matches:**
```json
{
  "creditCard": "4532015112830366",         // REDACTED (valid Luhn)
  "card_number": "5425233430109903"         // REDACTED (valid Luhn)
}
```

**Example Non-Matches (v1.0+):**
```json
{
  "text": "Order 4532-1234-5678-9010"       // NOT REDACTED (fails Luhn)
}
```

**✅ v1.0 Change:** Luhn validation is **now enabled** to reduce false positives on order numbers, tracking codes, etc. Only valid credit card numbers are detected.

### IP Addresses

**⚠️ REMOVED in v1.0:**
- IPv4 and IPv6 patterns have been removed from default PII detection
- **Rationale:** IP addresses rarely qualify as PII under GDPR/PDPA
- **Issue:** Caused false positives on version numbers (e.g., `v1.2.3.4`), configuration values

**Migration:** If you need IP detection, add custom patterns:
```go
config.CustomContentPatterns = append(config.CustomContentPatterns,
    ContentPattern{
        Name: "ipv4",
        Pattern: regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
    },
)
```

~~**Content Pattern:**~~
~~```regex~~
~~\b(?:\d{1,3}\.){3}\d{1,3}\b~~
~~```~~

**Field Names:**
- `ip`, `ipAddress`, `ip_address`, `clientIp`, `client_ip`
- `remoteIp`, `remote_ip`, `sourceIp`, `destinationIp`

**Validator:** Validates octet ranges (0-255)

**Example Matches:**
```json
{
  "ip": "192.168.1.1",                     // REDACTED
  "message": "Request from 10.0.0.5"       // Content: REDACTED
}
```

### Secrets & Credentials

**Field Names:**
- `password`, `passwd`, `pwd`, `secret`
- `token`, `accessToken`, `access_token`, `refreshToken`
- `apiKey`, `api_key`, `privateKey`, `private_key`
- `credential`, `credentials`, `auth`, `authorization`
- `bearer`, `sessionId`, `session_id`, `otp`, `pin`

**Example Matches:**
```json
{
  "password": "MySecretPass123!",          // REDACTED
  "apiKey": "sk_live_abc123xyz",           // REDACTED
  "token": "eyJhbGciOiJIUzI1NiIs..."       // REDACTED
}
```

---

## Regional Patterns

Regional patterns are enabled based on the configured regions.

### Singapore 🇸🇬

**Enable:** `WithRegions(Singapore)`

#### NRIC (National Registration Identity Card)

**Format:** `S/T/F/G/M + 7 digits + checksum letter`

**Content Pattern:**
```regex
(?i)\b[STFGM]\d{7}[A-Z]\b
```

**Validation (v1.0+):** Checksum validation using weighted algorithm
- **Weights:** [2, 7, 6, 5, 4, 3, 2]
- **Offset:** +4 for T/G prefixes
- **Checksum tables:** ST="JZIHGFEDCBA", FG="XWUTRQPNMLK"

**Field Names:**
- `nric`, `ic`, `identityCard`, `identity_card`, `nationalId`

**Examples (v1.0+ with checksum validation):**
- `S1234567D` ✅ (valid checksum)
- `T1234567J` ✅ (valid checksum)
- `F1234567N` ✅ (valid checksum)

**Non-Matches (invalid checksums):**
- `S1234567A` ❌ (fails checksum)
- `T9876543Z` ❌ (fails checksum)

#### Singapore Phone Numbers

**Format:** `+65` or `65` or `6/8/9` prefix + 7-8 digits

**Content Pattern:**
```regex
(?:\+65|65)?[689]\d{7}
```

**Examples:**
- `+6591234567` ✅
- `91234567` ✅
- `65812345678` ✅

#### Singapore Bank Accounts

**⚠️ v1.0 Change:** Content pattern removed (field name matching only)

**Detection Method:** Field name matching ONLY
- `accountNumber`, `account_number`, `bankAccount`, `bank_account`, `iban`

**Rationale:** Generic digit patterns caused too many false positives on order IDs, transaction IDs, etc.

~~**Format:** 7-11 digits, sometimes with dashes~~

~~**Content Pattern:**~~
~~```regex~~
~~\b\d{4}-\d{3}-\d{7,11}\b|\b\d{7,11}\b~~
~~```~~

**Examples:**
- Field name `accountNumber` with any value ✅
- Random 10-digit number in text ❌ (no longer detected)

---

### Malaysia 🇲🇾

**Enable:** `WithRegions(Malaysia)`

#### MyKad (Malaysian Identity Card)

**Format:** `YYMMDD-PB-###G` (12 digits with dashes)
- `YYMMDD`: Date of birth
- `PB`: Place of birth code
- `###`: Sequence number

**Validation (v1.0+):** Date validation
- **Month:** Must be 01-12
- **Day:** Must be 01-31 (with month-specific limits)
- **Example valid:** `901230-14-5678` (Dec 30, 1990)
- **Example invalid:** `991340-14-5678` (month 13 doesn't exist)
- `G`: Gender (odd=male, even=female)

**Content Pattern:**
```regex
\b\d{6}-?\d{2}-?\d{4}\b
```

**Field Names:**
- `mykad`, `ic`, `identityCard`, `identity_card`, `nric`

**Examples:**
- `901230-14-5678` ✅
- `850615-10-1234` ✅
- `901230145678` ✅ (without dashes)

#### Malaysia Phone Numbers

**Format:** `+60` or `60` or `0` + 9-10 digits

**Content Pattern:**
```regex
(?:\+60|60|0)1\d{8,9}
```

**Examples:**
- `+60123456789` ✅
- `0123456789` ✅
- `60198765432` ✅

#### Malaysia Bank Accounts

**Format:** 7-16 digits (varies by bank)

**Content Pattern:**
```regex
\b\d{7,16}\b
```

**Examples:**
- `1234567890123` ✅
- `12345678` ✅

---

### UAE 🇦🇪

**Enable:** `WithRegions(UAE)`

#### Emirates ID

**Format:** `784-YYYY-XXXXXXX-D` (15 digits)
- `784`: UAE country code
- `YYYY`: Year
- `XXXXXXX`: Serial number
- `D`: Check digit

**Content Pattern:**
```regex
\b784-?\d{4}-?\d{7}-?\d\b
```

**Field Names:**
- `emiratesId`, `emirates_id`, `eid`, `uaeId`, `identityCard`

**Examples:**
- `784-2020-1234567-1` ✅
- `78420201234567` ✅
- `784-1990-7654321-9` ✅

#### UAE IBAN

**Format:** `AE` + 2 check digits + 19 digits (23 characters total)

**Content Pattern:**
```regex
\bAE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b
```

**Field Names:**
- `iban`, `accountNumber`, `account_number`, `bankAccount`

**Examples:**
- `AE07 0331 2345 6789 0123 456` ✅
- `AE070331234567890123456` ✅

#### UAE Phone Numbers

**Format:** `+971` or `00971` or `0` + area/mobile code + 7 digits

**Content Pattern:**
```regex
(?:\+971|00971|0)(?:2|3|4|6|7|9|50|51|52|54|55|56|58)\d{7}
```

**Examples:**
- `+971501234567` ✅
- `0501234567` ✅
- `971521234567` ✅

---

### Thailand 🇹🇭

**Enable:** `WithRegions(Thailand)`

#### Thailand National ID

**Format:** `X-XXXX-XXXXX-XX-X` (13 digits with check digit)

**Content Pattern:**
```regex
\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b
```

**Field Names:**
- `nationalId`, `national_id`, `idCard`, `id_card`, `citizenId`

**Examples:**
- `1-2345-67890-12-3` ✅
- `1234567890123` ✅ (without dashes)

#### Thailand Phone Numbers

**Format:** `+66` or `66` or `0` + 8-9 digits (mobile: 6/8/9 prefix)

**Content Pattern:**
```regex
(?:\+66|66|0)[689]\d{8}
```

**Examples:**
- `+66812345678` ✅
- `0812345678` ✅
- `66912345678` ✅

#### Thailand Bank Accounts

**Format:** Usually 10 digits (format varies: `XXX-X-XXXXX-X`)

**Content Pattern:**
```regex
\b\d{3}-?\d-?\d{5}-?\d\b|\b\d{10,12}\b
```

**Examples:**
- `012-3-45678-9` ✅
- `1234567890` ✅

---

### Hong Kong 🇭🇰

**Enable:** `WithRegions(HongKong)`

#### HKID (Hong Kong Identity Card)

**Format:** `[A-Z]{1,2} + 6 digits + (check digit)` or without parentheses

**Content Pattern:**
```regex
(?i)\b[A-Z]{1,2}\d{6}\([A0-9]\)|\b[A-Z]{1,2}\d{6}[A0-9]\b
```

**Field Names:**
- `hkid`, `identityCard`, `identity_card`, `idCard`, `ic`

**Examples:**
- `A123456(7)` ✅
- `AB1234567` ✅
- `K9876543` ✅

#### Hong Kong Phone Numbers

**Format:** `+852` or `852` + 8 digits

**Content Pattern:**
```regex
(?:\+852|852)?\d{8}
```

**Examples:**
- `+85291234567` ✅
- `91234567` ✅
- `85223456789` ✅

#### Hong Kong Bank Accounts

**Format:** 9-12 digits (varies by bank)

**Content Pattern:**
```regex
\b\d{9,12}\b
```

**Examples:**
- `123456789` ✅
- `123456789012` ✅

---

## Custom Patterns

You can add custom patterns to detect domain-specific PII.

### Custom Field Patterns

```go
config := NewDefaultConfig()
config.CustomFieldPatterns = map[string][]string{
    "internal_reference": {"internalRef", "internal_ref", "refCode"},
    "employee_id": {"employeeId", "employee_id", "staffId"},
}
s := New(config)
```

**Example:**
```json
{
  "internalRef": "REF-12345",    // REDACTED (matches custom pattern)
  "employeeId": "EMP-9876"       // REDACTED (matches custom pattern)
}
```

### Custom Content Patterns

```go
customPattern := ContentPattern{
    Name:    "customer_id",
    Pattern: regexp.MustCompile(`\bCUST-\d{6}\b`),
}

config := NewDefaultConfig()
config.CustomContentPatterns = []ContentPattern{customPattern}
s := New(config)
```

**Example:**
```json
{
  "note": "Customer CUST-123456 requested refund"  // Content: REDACTED
}
```

### Custom Content Patterns with Validators

```go
customPattern := ContentPattern{
    Name:    "order_reference",
    Pattern: regexp.MustCompile(`\bORD-\d{4,8}\b`),
    Validator: func(s string) bool {
        // Custom validation logic
        return len(s) >= 8
    },
}
```

---

## Pattern Priority

The sanitizer evaluates patterns in this priority order:

1. **Explicit Preserve List** (`NeverRedact`) - Highest priority, value never redacted
2. **Explicit Redact List** (`AlwaysRedact`) - Value always redacted
3. **Field Name Patterns** - Matches field names against common PII patterns
4. **Content Patterns** - Matches field values against regex patterns

```go
// Example: Configure priority
config := NewDefaultConfig().
    WithPreserve("orderId", "transactionId").  // Never redacted
    WithRedact("debugInfo", "internalNotes")    // Always redacted

s := New(config)
```

---

## Detection Methods

### Field Name Matching

Case-insensitive matching of field names against known PII field patterns.

**Example:**
- `email` → matches "email" pattern
- `Email` → matches "email" pattern (case-insensitive)
- `user_email` → matches "email" pattern
- `EMAIL_ADDRESS` → matches "email" pattern

### Content Pattern Matching

Regex-based matching of field **values** against PII patterns.

**Example:**
```go
// Field name doesn't match, but content does
{
  "message": "Contact us at support@example.com"  // REDACTED (email in content)
}
```

### Combined Detection

Both field name AND content are checked.

**Example:**
```go
{
  "email": "user@example.com",           // REDACTED (field name + content)
  "message": "Email: user@example.com",  // REDACTED (content only)
  "userEmail": "someone@test.com"        // REDACTED (field name + content)
}
```

---

## Regional Configuration Examples

### Single Region

```go
// Only Singapore patterns
s := NewForRegion(Singapore)
```

### Multiple Regions

```go
// Singapore + Malaysia patterns
config := NewDefaultConfig().WithRegions(Singapore, Malaysia)
s := New(config)
```

### All Regions (Default)

```go
// All regions enabled
s := NewDefault()
```

---

## Performance Considerations

- **Pre-compiled Patterns**: All regex patterns are compiled once during initialization
- **Case-Insensitive Matching**: Field names converted to lowercase for faster comparison
- **Explicit List Lookups**: O(1) map lookups for explicit redact/preserve lists
- **Early Exit**: Processing stops as soon as a match is found (priority order)

**Recommendation**: Enable only the regions you need to minimize pattern matching overhead.

```go
// Faster (fewer patterns)
s := NewForRegion(Singapore)

// Slower (all region patterns enabled)
s := NewDefault()
```

---

## False Positives & Tuning

### Reducing False Positives

Use explicit preserve lists for business IDs:

```go
config := NewDefaultConfig().
    WithPreserve("orderId", "productId", "transactionId", "sessionId")
s := New(config)
```

### Increasing Detection (Lower False Negatives)

Add custom patterns for domain-specific PII:

```go
config := NewDefaultConfig().
    WithRedact("customerNotes", "internalComments", "debugData")
s := New(config)
```

---

## Compliance Mapping

| Regulation | Relevant Patterns |
|------------|-------------------|
| Singapore PDPA | NRIC, email, phone, address, bank accounts |
| Malaysia PDPA | MyKad, email, phone, address, bank accounts |
| UAE Data Protection | Emirates ID, IBAN, email, phone, address |
| Thailand PDPA | National ID, email, phone, address, bank accounts |
| Hong Kong PDPO | HKID, email, phone, address, bank accounts |

See [COMPLIANCE.md](./COMPLIANCE.md) for detailed compliance information.
