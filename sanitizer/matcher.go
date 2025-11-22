package sanitizer

import (
	"regexp"
	"strings"
)

// fieldNameMatcher handles matching field names against PII patterns
type fieldNameMatcher struct {
	patterns map[string]*regexp.Regexp // compiled regex patterns for field names
}

// newFieldNameMatcher creates a new field name matcher with compiled patterns
func newFieldNameMatcher(fieldNames map[string][]string, secretNames []string) *fieldNameMatcher {
	matcher := &fieldNameMatcher{
		patterns: make(map[string]*regexp.Regexp),
	}

	// Compile patterns for each PII type
	for piiType, names := range fieldNames {
		// Create regex pattern that matches any of the field names (case-insensitive)
		escapedNames := make([]string, len(names))
		for i, name := range names {
			escapedNames[i] = regexp.QuoteMeta(name)
		}
		pattern := "(?i)^(" + strings.Join(escapedNames, "|") + ")$"
		matcher.patterns[piiType] = regexp.MustCompile(pattern)
	}

	// Add secret field names with highest priority
	if len(secretNames) > 0 {
		escapedNames := make([]string, len(secretNames))
		for i, name := range secretNames {
			escapedNames[i] = regexp.QuoteMeta(name)
		}
		pattern := "(?i)^(" + strings.Join(escapedNames, "|") + ")$"
		matcher.patterns["secret"] = regexp.MustCompile(pattern)
	}

	return matcher
}

// matches checks if a field name matches any PII pattern
func (m *fieldNameMatcher) matches(fieldName string) bool {
	for _, pattern := range m.patterns {
		if pattern.MatchString(fieldName) {
			return true
		}
	}
	return false
}

// matchType returns the PII type if field name matches, empty string otherwise
func (m *fieldNameMatcher) matchType(fieldName string) string {
	// Check secrets first (highest priority)
	if pattern, exists := m.patterns["secret"]; exists && pattern.MatchString(fieldName) {
		return "secret"
	}

	// Check other patterns
	for piiType, pattern := range m.patterns {
		if piiType != "secret" && pattern.MatchString(fieldName) {
			return piiType
		}
	}

	return ""
}

// contentMatcher handles matching field values against content patterns
type contentMatcher struct {
	patterns []ContentPattern
}

// newContentMatcher creates a new content matcher
func newContentMatcher(patterns []ContentPattern) *contentMatcher {
	return &contentMatcher{
		patterns: patterns,
	}
}

// matches checks if content matches any PII pattern
func (m *contentMatcher) matches(content string) bool {
	for _, pattern := range m.patterns {
		matches := pattern.Pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			// If validator exists, use it on each match
			if pattern.Validator != nil {
				for _, match := range matches {
					if pattern.Validator(match) {
						return true
					}
				}
			} else {
				return true
			}
		}
	}
	return false
}

// matchType returns the PII type if content matches, empty string otherwise
func (m *contentMatcher) matchType(content string) string {
	for _, pattern := range m.patterns {
		matches := pattern.Pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			// If validator exists, use it on each match
			if pattern.Validator != nil {
				for _, match := range matches {
					if pattern.Validator(match) {
						return pattern.Name
					}
				}
			} else {
				return pattern.Name
			}
		}
	}
	return ""
}
