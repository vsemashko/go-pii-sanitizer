package sanitizer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigFile represents the structure of a YAML/JSON configuration file
// This provides a more user-friendly format for configuration files
type ConfigFile struct {
	Regions        []string          `yaml:"regions" json:"regions"`
	Strategy       string            `yaml:"strategy" json:"strategy"`
	AlwaysRedact   []string          `yaml:"always_redact" json:"always_redact"`
	NeverRedact    []string          `yaml:"never_redact" json:"never_redact"`
	PartialMasking *PartialMasking   `yaml:"partial_masking" json:"partial_masking"`
	HashSalt       string            `yaml:"hash_salt" json:"hash_salt"`
	MaxDepth       *int              `yaml:"max_depth" json:"max_depth"`
	CustomPatterns *CustomPatterns   `yaml:"custom_patterns" json:"custom_patterns"`
}

// PartialMasking configuration in file format
type PartialMasking struct {
	MaskChar  string `yaml:"mask_char" json:"mask_char"`
	KeepLeft  int    `yaml:"keep_left" json:"keep_left"`
	KeepRight int    `yaml:"keep_right" json:"keep_right"`
}

// CustomPatterns configuration in file format
type CustomPatterns struct {
	Fields  map[string][]string `yaml:"fields" json:"fields"`
	Content []ContentPatternDef `yaml:"content" json:"content"`
}

// ContentPatternDef defines a custom content pattern in file format
type ContentPatternDef struct {
	Name    string `yaml:"name" json:"name"`
	Pattern string `yaml:"pattern" json:"pattern"`
}

// LoadConfig loads sanitizer configuration from a YAML or JSON file.
// The file format is detected automatically based on the file extension (.yaml, .yml, or .json).
//
// Example YAML file:
//
//	regions:
//	  - SG
//	  - MY
//	strategy: partial
//	always_redact:
//	  - internalNotes
//	  - debugInfo
//	never_redact:
//	  - orderId
//	  - transactionId
//	partial_masking:
//	  mask_char: "*"
//	  keep_left: 0
//	  keep_right: 4
//	hash_salt: "my-secret-salt"
//	max_depth: 10
//	custom_patterns:
//	  fields:
//	    custom_id:
//	      - customerId
//	      - customer_id
//	  content:
//	    - name: custom_pattern
//	      pattern: "[A-Z]{3}-\\d{6}"
//
// The same structure works for JSON files.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var configFile ConfigFile
	ext := strings.ToLower(filepath.Ext(filename))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &configFile); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &configFile); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s (use .yaml, .yml, or .json)", ext)
	}

	return configFile.ToConfig()
}

// ToConfig converts a ConfigFile to a Config
func (cf *ConfigFile) ToConfig() (*Config, error) {
	config := NewDefaultConfig()

	// Parse regions
	// If regions is explicitly set (even if empty), use it
	if cf.Regions != nil {
		regions := make([]Region, 0, len(cf.Regions))
		for _, r := range cf.Regions {
			region, err := parseRegion(r)
			if err != nil {
				return nil, err
			}
			regions = append(regions, region)
		}
		config.Regions = regions
	}

	// Parse strategy
	if cf.Strategy != "" {
		strategy, err := parseStrategy(cf.Strategy)
		if err != nil {
			return nil, err
		}
		config.Strategy = strategy
	}

	// Set explicit lists
	if len(cf.AlwaysRedact) > 0 {
		config.AlwaysRedact = cf.AlwaysRedact
	}
	if len(cf.NeverRedact) > 0 {
		config.NeverRedact = cf.NeverRedact
	}

	// Parse partial masking
	if cf.PartialMasking != nil {
		if cf.PartialMasking.MaskChar != "" {
			if len([]rune(cf.PartialMasking.MaskChar)) != 1 {
				return nil, fmt.Errorf("mask_char must be a single character, got: %s", cf.PartialMasking.MaskChar)
			}
			config.PartialMaskChar = []rune(cf.PartialMasking.MaskChar)[0]
		}
		config.PartialKeepLeft = cf.PartialMasking.KeepLeft
		config.PartialKeepRight = cf.PartialMasking.KeepRight
	}

	// Set hash salt
	if cf.HashSalt != "" {
		config.HashSalt = cf.HashSalt
	}

	// Set max depth
	// If max_depth is explicitly set, use it (even if invalid - Validate will catch it)
	if cf.MaxDepth != nil {
		config.MaxDepth = *cf.MaxDepth
	}

	// Parse custom patterns
	if cf.CustomPatterns != nil {
		if len(cf.CustomPatterns.Fields) > 0 {
			config.CustomFieldPatterns = cf.CustomPatterns.Fields
		}

		if len(cf.CustomPatterns.Content) > 0 {
			patterns := make([]ContentPattern, 0, len(cf.CustomPatterns.Content))
			for _, p := range cf.CustomPatterns.Content {
				pattern, err := compileContentPattern(p)
				if err != nil {
					return nil, fmt.Errorf("failed to compile custom pattern '%s': %w", p.Name, err)
				}
				patterns = append(patterns, pattern)
			}
			config.CustomContentPatterns = patterns
		}
	}

	// Validate the final configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// parseRegion converts a string to a Region constant
func parseRegion(s string) (Region, error) {
	regionMap := map[string]Region{
		"SG": Singapore,
		"MY": Malaysia,
		"AE": UAE,
		"TH": Thailand,
		"HK": HongKong,
		"ID": Indonesia,
		"PH": Philippines,
		"VN": Vietnam,
		"KR": SouthKorea,
	}

	upper := strings.ToUpper(s)
	if region, ok := regionMap[upper]; ok {
		return region, nil
	}

	return "", fmt.Errorf("invalid region: %s (valid: SG, MY, AE, TH, HK, ID, PH, VN, KR)", s)
}

// parseStrategy converts a string to a RedactionStrategy constant
func parseStrategy(s string) (RedactionStrategy, error) {
	strategyMap := map[string]RedactionStrategy{
		"full":    StrategyFull,
		"partial": StrategyPartial,
		"hash":    StrategyHash,
		"remove":  StrategyRemove,
	}

	lower := strings.ToLower(s)
	if strategy, ok := strategyMap[lower]; ok {
		return strategy, nil
	}

	return "", fmt.Errorf("invalid strategy: %s (valid: full, partial, hash, remove)", s)
}

// compileContentPattern compiles a ContentPatternDef into a ContentPattern
func compileContentPattern(def ContentPatternDef) (ContentPattern, error) {
	pattern, err := regexp.Compile(def.Pattern)
	if err != nil {
		return ContentPattern{}, err
	}

	return ContentPattern{
		Name:    def.Name,
		Pattern: pattern,
	}, nil
}
