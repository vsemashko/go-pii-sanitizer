package sanitizer

import (
	"go.uber.org/zap/zapcore"
)

// ZapObject wraps data for sanitization in zap logging
// Implements zapcore.ObjectMarshaler
type ZapObject struct {
	sanitizer *Sanitizer
	data      interface{}
}

// MarshalLogObject implements zapcore.ObjectMarshaler
func (z ZapObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	var m map[string]interface{}

	switch val := z.data.(type) {
	case map[string]interface{}:
		m = z.sanitizer.SanitizeMap(val)
	default:
		m = z.sanitizer.SanitizeStruct(val)
	}

	return marshalMap(enc, m)
}

// marshalMap recursively marshals a map into the zap encoder
func marshalMap(enc zapcore.ObjectEncoder, m map[string]interface{}) error {
	for k, v := range m {
		if err := addField(enc, k, v); err != nil {
			return err
		}
	}
	return nil
}

// addField adds a field to the encoder with appropriate type handling
func addField(enc zapcore.ObjectEncoder, key string, value interface{}) error {
	switch val := value.(type) {
	case string:
		enc.AddString(key, val)
	case int:
		enc.AddInt(key, val)
	case int64:
		enc.AddInt64(key, val)
	case float64:
		enc.AddFloat64(key, val)
	case bool:
		enc.AddBool(key, val)
	case map[string]interface{}:
		return enc.AddObject(key, zapcore.ObjectMarshalerFunc(func(innerEnc zapcore.ObjectEncoder) error {
			return marshalMap(innerEnc, val)
		}))
	case []interface{}:
		return enc.AddArray(key, zapcore.ArrayMarshalerFunc(func(arrEnc zapcore.ArrayEncoder) error {
			return marshalSlice(arrEnc, val)
		}))
	case nil:
		enc.AddReflected(key, nil)
	default:
		// For unknown types, use reflection
		enc.AddReflected(key, val)
	}
	return nil
}

// marshalSlice marshals a slice into the zap array encoder
func marshalSlice(enc zapcore.ArrayEncoder, slice []interface{}) error {
	for _, v := range slice {
		switch val := v.(type) {
		case string:
			enc.AppendString(val)
		case int:
			enc.AppendInt(val)
		case int64:
			enc.AppendInt64(val)
		case float64:
			enc.AppendFloat64(val)
		case bool:
			enc.AppendBool(val)
		case map[string]interface{}:
			if err := enc.AppendObject(zapcore.ObjectMarshalerFunc(func(objEnc zapcore.ObjectEncoder) error {
				return marshalMap(objEnc, val)
			})); err != nil {
				return err
			}
		case []interface{}:
			if err := enc.AppendArray(zapcore.ArrayMarshalerFunc(func(arrEnc zapcore.ArrayEncoder) error {
				return marshalSlice(arrEnc, val)
			})); err != nil {
				return err
			}
		default:
			enc.AppendReflected(val)
		}
	}
	return nil
}

// ZapObject creates a ZapObject for use in zap logging
func (s *Sanitizer) ZapObject(value interface{}) ZapObject {
	return ZapObject{sanitizer: s, data: value}
}

// ZapString sanitizes a string field for zap
func (s *Sanitizer) ZapString(key, value string) zapcore.Field {
	sanitized := s.SanitizeField(key, value)
	return zapcore.Field{
		Key:    key,
		Type:   zapcore.StringType,
		String: sanitized,
	}
}

// ZapField creates a sanitized zap field from any value
func (s *Sanitizer) ZapField(key string, value interface{}) zapcore.Field {
	return zapcore.Field{
		Key:       key,
		Type:      zapcore.ObjectMarshalerType,
		Interface: s.ZapObject(value),
	}
}
