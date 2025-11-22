package sanitizer

import (
	"encoding/json"
	"strings"
)

// Sanitizer is the main PII sanitization engine
type Sanitizer struct {
	config         *Config
	fieldMatcher   *fieldNameMatcher
	contentMatcher *contentMatcher
	explicitRedact map[string]bool // Quick lookup for AlwaysRedact
	explicitSafe   map[string]bool // Quick lookup for NeverRedact
}

// New creates a new Sanitizer with the given configuration
func New(config *Config) *Sanitizer {
	if config == nil {
		config = NewDefaultConfig()
	}

	s := &Sanitizer{
		config:         config,
		explicitRedact: make(map[string]bool),
		explicitSafe:   make(map[string]bool),
	}

	// Build explicit redact/safe maps for quick lookup
	for _, field := range config.AlwaysRedact {
		s.explicitRedact[strings.ToLower(field)] = true
	}
	for _, field := range config.NeverRedact {
		s.explicitSafe[strings.ToLower(field)] = true
	}

	// Compile patterns
	s.compilePatterns()

	return s
}

// NewDefault creates a sanitizer with default configuration for all regions
func NewDefault() *Sanitizer {
	return New(NewDefaultConfig())
}

// NewForRegion creates a sanitizer for specific region(s)
func NewForRegion(regions ...Region) *Sanitizer {
	config := NewDefaultConfig()
	config.Regions = regions
	return New(config)
}

// compilePatterns compiles all regex patterns for the configured regions
func (s *Sanitizer) compilePatterns() {
	// Collect field names from common patterns
	commonFieldNames := getCommonFieldNames()
	secretFieldNames := getSecretFieldNames()

	// Merge field names from all sources
	allFieldNames := make(map[string][]string)
	for piiType, names := range commonFieldNames {
		allFieldNames[piiType] = names
	}

	// Add regional field names
	allRegionalPatterns := getAllRegionalPatterns()
	for _, regional := range allRegionalPatterns {
		// Only include if region is enabled
		regionEnabled := false
		for _, enabledRegion := range s.config.Regions {
			if regional.Region == enabledRegion {
				regionEnabled = true
				break
			}
		}

		if regionEnabled {
			key := string(regional.Region)
			allFieldNames[key] = regional.FieldNames
		}
	}

	// Add custom field patterns
	for piiType, names := range s.config.CustomFieldPatterns {
		if existing, exists := allFieldNames[piiType]; exists {
			allFieldNames[piiType] = append(existing, names...)
		} else {
			allFieldNames[piiType] = names
		}
	}

	// Create field name matcher
	s.fieldMatcher = newFieldNameMatcher(allFieldNames, secretFieldNames)

	// Collect content patterns
	contentPatterns := getCommonContentPatterns()

	// Add regional content patterns
	for _, regional := range allRegionalPatterns {
		regionEnabled := false
		for _, enabledRegion := range s.config.Regions {
			if regional.Region == enabledRegion {
				regionEnabled = true
				break
			}
		}

		if regionEnabled {
			contentPatterns = append(contentPatterns, regional.ContentPatterns...)
		}
	}

	// Add custom content patterns
	contentPatterns = append(contentPatterns, s.config.CustomContentPatterns...)

	// Create content matcher
	s.contentMatcher = newContentMatcher(contentPatterns)
}

// SanitizeField sanitizes a single field value
func (s *Sanitizer) SanitizeField(fieldName, value string) string {
	// Don't redact empty values
	if value == "" {
		return value
	}

	// 1. Check explicit lists first (highest priority)
	fieldNameLower := strings.ToLower(fieldName)

	// Never redact if in safe list
	if s.explicitSafe[fieldNameLower] {
		return value
	}

	// Always redact if in redact list
	if s.explicitRedact[fieldNameLower] {
		return s.redact(value)
	}

	// 2. Check field name patterns
	if s.fieldMatcher.matches(fieldName) {
		return s.redact(value)
	}

	// 3. Check content patterns (only for string values)
	if s.contentMatcher.matches(value) {
		return s.redact(value)
	}

	// No PII detected
	return value
}

// SanitizeMap sanitizes a map (common for JSON-like structures)
func (s *Sanitizer) SanitizeMap(m map[string]interface{}) map[string]interface{} {
	return s.sanitizeMapRecursive(m, 0)
}

// sanitizeMapRecursive sanitizes a map recursively with depth tracking
func (s *Sanitizer) sanitizeMapRecursive(m map[string]interface{}, depth int) map[string]interface{} {
	if depth > s.config.MaxDepth {
		return m
	}

	result := make(map[string]interface{})
	for k, v := range m {
		switch val := v.(type) {
		case string:
			sanitized := s.SanitizeField(k, val)
			// If strategy is Remove and value was redacted, skip this field
			if s.config.Strategy == StrategyRemove && sanitized == "" && val != "" {
				continue
			}
			result[k] = sanitized

		case map[string]interface{}:
			result[k] = s.sanitizeMapRecursive(val, depth+1)

		case []interface{}:
			result[k] = s.sanitizeSlice(val, depth+1)

		default:
			// For non-string types, preserve as-is
			result[k] = val
		}
	}
	return result
}

// sanitizeSlice sanitizes a slice recursively
func (s *Sanitizer) sanitizeSlice(slice []interface{}, depth int) []interface{} {
	if depth > s.config.MaxDepth {
		return slice
	}

	result := make([]interface{}, len(slice))
	for i, v := range slice {
		switch val := v.(type) {
		case string:
			// For slices, we don't have field names, so only check content
			if s.contentMatcher.matches(val) {
				result[i] = s.redact(val)
			} else {
				result[i] = val
			}

		case map[string]interface{}:
			result[i] = s.sanitizeMapRecursive(val, depth+1)

		case []interface{}:
			result[i] = s.sanitizeSlice(val, depth+1)

		default:
			result[i] = val
		}
	}
	return result
}

// SanitizeJSON sanitizes JSON data
func (s *Sanitizer) SanitizeJSON(data []byte) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	sanitized := s.SanitizeMap(m)
	return json.Marshal(sanitized)
}

// SanitizeStruct sanitizes a struct by converting it to a map
// This uses JSON marshaling/unmarshaling which has overhead but works with any struct
func (s *Sanitizer) SanitizeStruct(v interface{}) map[string]interface{} {
	// Convert struct to JSON, then to map
	data, err := json.Marshal(v)
	if err != nil {
		// If marshaling fails, return empty map
		return make(map[string]interface{})
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]interface{})
	}

	return s.SanitizeMap(m)
}
