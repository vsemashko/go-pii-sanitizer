package sanitizer

import (
	"log/slog"
)

// SlogValue wraps data for sanitization in slog logging
// Implements slog.LogValuer for zero-allocation integration
type SlogValue struct {
	sanitizer *Sanitizer
	data      any
}

// LogValue implements slog.LogValuer
// This method is called by slog when the value is logged
func (v SlogValue) LogValue() slog.Value {
	switch val := v.data.(type) {
	case map[string]any:
		sanitized := v.sanitizer.SanitizeMap(val)
		return mapToSlogValue(sanitized)

	case string:
		// If it's a string, check if it contains PII patterns
		if v.sanitizer.contentMatcher.matches(val) {
			return slog.StringValue(v.sanitizer.redact(val))
		}
		return slog.StringValue(val)

	default:
		// For structs and other types, convert to map first
		sanitized := v.sanitizer.SanitizeStruct(val)
		return mapToSlogValue(sanitized)
	}
}

// mapToSlogValue recursively converts a sanitized map to slog.Value
func mapToSlogValue(m map[string]any) slog.Value {
	attrs := make([]slog.Attr, 0, len(m))
	for k, v := range m {
		attrs = append(attrs, slog.Any(k, convertToSlogValue(v)))
	}
	return slog.GroupValue(attrs...)
}

// convertToSlogValue converts any to appropriate slog value
func convertToSlogValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return mapToSlogValue(val)
	case []any:
		// Convert slice elements
		result := make([]any, len(val))
		for i, item := range val {
			result[i] = convertToSlogValue(item)
		}
		return result
	default:
		return val
	}
}

// SlogAttr creates an slog.Attr with sanitized data
func (s *Sanitizer) SlogAttr(key string, value any) slog.Attr {
	return slog.Any(key, SlogValue{sanitizer: s, data: value})
}

// SlogValue creates a SlogValue for use in slog logging
func (s *Sanitizer) SlogValue(value any) SlogValue {
	return SlogValue{sanitizer: s, data: value}
}

// SlogString sanitizes a string field for slog
func (s *Sanitizer) SlogString(key, value string) slog.Attr {
	sanitized := s.SanitizeField(key, value)
	return slog.String(key, sanitized)
}

// SlogGroup creates a sanitized group attribute
func (s *Sanitizer) SlogGroup(name string, args ...any) slog.Attr {
	// Convert args to map
	m := make(map[string]any)
	for i := 0; i < len(args)-1; i += 2 {
		if key, ok := args[i].(string); ok {
			m[key] = args[i+1]
		}
	}
	return slog.Any(name, s.SlogValue(m))
}
