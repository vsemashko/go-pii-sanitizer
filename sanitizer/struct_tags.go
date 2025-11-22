package sanitizer

import (
	"reflect"
	"strings"
)

// Struct tag support for explicit PII marking
// Usage:
//   type User struct {
//       Email    string `pii:"redact"`
//       FullName string `pii:"redact"`
//       OrderID  string `pii:"preserve"`
//       Notes    string `pii:"redact,sensitive"`
//   }

const piiTagName = "pii"

// PIITag represents the parsed PII tag value
type piiTag struct {
	action    string // "redact", "preserve", or empty
	sensitive bool   // "sensitive" flag
}

// parsePIITag parses a PII struct tag
// Format: `pii:"redact"` or `pii:"preserve"` or `pii:"redact,sensitive"`
func parsePIITag(tag string) *piiTag {
	if tag == "" {
		return nil
	}

	parts := strings.Split(tag, ",")
	pt := &piiTag{
		action: strings.TrimSpace(parts[0]),
	}

	// Check for additional flags
	for i := 1; i < len(parts); i++ {
		flag := strings.TrimSpace(parts[i])
		if flag == "sensitive" {
			pt.sensitive = true
		}
	}

	return pt
}

// SanitizeStructWithTags sanitizes a struct using struct tags for explicit PII marking.
// This method respects `pii` struct tags:
//   - `pii:"redact"` - Always redact this field
//   - `pii:"preserve"` - Never redact this field (highest priority)
//   - `pii:"redact,sensitive"` - Redact and mark as sensitive
//
// Tag priority: preserve > redact > pattern matching
//
// Example:
//
//	type User struct {
//	    Email    string `json:"email" pii:"redact"`
//	    FullName string `json:"fullName" pii:"redact"`
//	    OrderID  string `json:"orderId" pii:"preserve"`
//	    Age      int    `json:"age"`  // Uses pattern matching
//	}
//
//	s := NewDefault()
//	result := s.SanitizeStructWithTags(user)
func (s *Sanitizer) SanitizeStructWithTags(v interface{}) map[string]interface{} {
	if v == nil {
		return make(map[string]interface{})
	}

	// Get reflect value
	val := reflect.ValueOf(v)

	// Handle pointers
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return make(map[string]interface{})
		}
		val = val.Elem()
	}

	// Only works with structs
	if val.Kind() != reflect.Struct {
		// Fallback to regular sanitization
		return s.SanitizeStruct(v)
	}

	return s.sanitizeStructValue(val, 0)
}

// sanitizeStructValue recursively sanitizes a struct value respecting tags
func (s *Sanitizer) sanitizeStructValue(val reflect.Value, depth int) map[string]interface{} {
	if depth > s.config.MaxDepth {
		return make(map[string]interface{})
	}

	result := make(map[string]interface{})
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Get JSON name (fallback to field name)
		jsonTag := fieldType.Tag.Get("json")
		fieldName := fieldType.Name
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" && parts[0] != "-" {
				fieldName = parts[0]
			}
		}

		// Parse PII tag
		piiTagValue := fieldType.Tag.Get(piiTagName)
		piiTag := parsePIITag(piiTagValue)

		// Apply tag-based logic
		sanitizedValue := s.sanitizeFieldWithTag(fieldName, field, piiTag, depth)
		result[fieldName] = sanitizedValue
	}

	return result
}

// sanitizeFieldWithTag sanitizes a single field value respecting its PII tag
func (s *Sanitizer) sanitizeFieldWithTag(fieldName string, field reflect.Value, tag *piiTag, depth int) interface{} {
	// Get the actual value
	fieldValue := field.Interface()

	// Handle nil values
	if !field.IsValid() || (field.Kind() == reflect.Ptr && field.IsNil()) {
		return nil
	}

	// Tag priority: preserve > redact > pattern matching
	if tag != nil {
		switch tag.action {
		case "preserve":
			// Never redact - return as-is
			return s.convertValue(fieldValue, depth)

		case "redact":
			// Always redact
			if field.Kind() == reflect.String {
				return s.redact(field.String())
			}
			// Non-string fields marked as redact: return redacted placeholder
			return "[REDACTED]"
		}
	}

	// No explicit tag - use pattern matching
	switch field.Kind() {
	case reflect.String:
		return s.SanitizeField(fieldName, field.String())

	case reflect.Struct:
		return s.sanitizeStructValue(field, depth+1)

	case reflect.Map:
		return s.sanitizeMapValue(field, depth+1)

	case reflect.Slice, reflect.Array:
		return s.sanitizeSliceValue(field, depth+1)

	case reflect.Ptr:
		if field.IsNil() {
			return nil
		}
		return s.sanitizeFieldWithTag(fieldName, field.Elem(), tag, depth)

	default:
		// Primitive types (int, float, bool, etc.)
		return fieldValue
	}
}

// convertValue converts a value for output (respecting preserve tag)
func (s *Sanitizer) convertValue(v interface{}, depth int) interface{} {
	if v == nil {
		return nil
	}

	val := reflect.ValueOf(v)

	switch val.Kind() {
	case reflect.Struct:
		return s.sanitizeStructValue(val, depth+1)

	case reflect.Map:
		return s.sanitizeMapValue(val, depth+1)

	case reflect.Slice, reflect.Array:
		return s.sanitizeSliceValue(val, depth+1)

	case reflect.Ptr:
		if val.IsNil() {
			return nil
		}
		return s.convertValue(val.Elem().Interface(), depth)

	default:
		return v
	}
}

// sanitizeMapValue sanitizes a map value
func (s *Sanitizer) sanitizeMapValue(val reflect.Value, depth int) interface{} {
	if depth > s.config.MaxDepth {
		return make(map[string]interface{})
	}

	if val.Kind() != reflect.Map {
		return val.Interface()
	}

	result := make(map[string]interface{})
	iter := val.MapRange()

	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Only handle string keys
		if key.Kind() != reflect.String {
			continue
		}

		keyStr := key.String()
		valueInterface := value.Interface()

		// Sanitize the value
		result[keyStr] = s.sanitizeValueRecursive(keyStr, valueInterface, depth+1)
	}

	return result
}

// sanitizeSliceValue sanitizes a slice/array value
func (s *Sanitizer) sanitizeSliceValue(val reflect.Value, depth int) interface{} {
	if depth > s.config.MaxDepth {
		return []interface{}{}
	}

	length := val.Len()
	result := make([]interface{}, length)

	for i := 0; i < length; i++ {
		item := val.Index(i)
		result[i] = s.sanitizeValueRecursive("", item.Interface(), depth+1)
	}

	return result
}

// sanitizeValueRecursive recursively sanitizes a value
func (s *Sanitizer) sanitizeValueRecursive(fieldName string, v interface{}, depth int) interface{} {
	if v == nil {
		return nil
	}

	if depth > s.config.MaxDepth {
		return v
	}

	val := reflect.ValueOf(v)

	switch val.Kind() {
	case reflect.String:
		return s.SanitizeField(fieldName, val.String())

	case reflect.Struct:
		return s.sanitizeStructValue(val, depth)

	case reflect.Map:
		return s.sanitizeMapValue(val, depth)

	case reflect.Slice, reflect.Array:
		return s.sanitizeSliceValue(val, depth)

	case reflect.Ptr:
		if val.IsNil() {
			return nil
		}
		return s.sanitizeValueRecursive(fieldName, val.Elem().Interface(), depth)

	default:
		return v
	}
}
