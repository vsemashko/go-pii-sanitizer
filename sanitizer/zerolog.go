package sanitizer

import (
	"github.com/rs/zerolog"
)

// ZerologObject wraps data for sanitization in zerolog logging
// Implements zerolog.LogObjectMarshaler
type ZerologObject struct {
	sanitizer *Sanitizer
	data      any
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler
func (z ZerologObject) MarshalZerologObject(e *zerolog.Event) {
	var m map[string]any

	switch val := z.data.(type) {
	case map[string]any:
		m = z.sanitizer.SanitizeMap(val)
	default:
		m = z.sanitizer.SanitizeStruct(val)
	}

	marshalZerologMap(e, m)
}

// marshalZerologMap marshals a map into zerolog event
func marshalZerologMap(e *zerolog.Event, m map[string]any) {
	for k, v := range m {
		addZerologField(e, k, v)
	}
}

// addZerologField adds a field to the event with appropriate type handling
func addZerologField(e *zerolog.Event, key string, value any) {
	switch val := value.(type) {
	case string:
		e.Str(key, val)
	case int:
		e.Int(key, val)
	case int64:
		e.Int64(key, val)
	case float64:
		e.Float64(key, val)
	case bool:
		e.Bool(key, val)
	case map[string]any:
		e.Object(key, zerologMapMarshaler{m: val})
	case []any:
		e.Array(key, zerologSliceMarshaler{slice: val})
	case nil:
		e.Interface(key, nil)
	default:
		// For unknown types, use interface
		e.Interface(key, val)
	}
}

// zerologMapMarshaler wraps a map for zerolog object marshaling
type zerologMapMarshaler struct {
	m map[string]any
}

func (zm zerologMapMarshaler) MarshalZerologObject(e *zerolog.Event) {
	marshalZerologMap(e, zm.m)
}

// zerologSliceMarshaler wraps a slice for zerolog array marshaling
type zerologSliceMarshaler struct {
	slice []any
}

func (zs zerologSliceMarshaler) MarshalZerologArray(a *zerolog.Array) {
	for _, v := range zs.slice {
		switch val := v.(type) {
		case string:
			a.Str(val)
		case int:
			a.Int(val)
		case int64:
			a.Int64(val)
		case float64:
			a.Float64(val)
		case bool:
			a.Bool(val)
		case map[string]any:
			a.Object(zerologMapMarshaler{m: val})
		case []any:
			// Nested arrays - use interface for simplicity
			a.Interface(val)
		default:
			a.Interface(val)
		}
	}
}

// ZerologObject creates a ZerologObject for use in zerolog logging
func (s *Sanitizer) ZerologObject(value any) ZerologObject {
	return ZerologObject{sanitizer: s, data: value}
}

// ZerologString sanitizes a string field for zerolog
func (s *Sanitizer) ZerologString(key, value string) (string, string) {
	sanitized := s.SanitizeField(key, value)
	return key, sanitized
}

// ZerologDict creates a sanitized zerolog dict event
func (s *Sanitizer) ZerologDict(value any) *zerolog.Event {
	return zerolog.Dict().Object("", s.ZerologObject(value))
}
