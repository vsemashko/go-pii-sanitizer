package sanitizer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_YAML(t *testing.T) {
	yamlContent := `
regions:
  - SG
  - MY
strategy: partial
always_redact:
  - internalNotes
  - debugInfo
never_redact:
  - orderId
  - transactionId
partial_masking:
  mask_char: "*"
  keep_left: 2
  keep_right: 4
hash_salt: "test-salt"
max_depth: 15
custom_patterns:
  fields:
    custom_id:
      - customerId
      - customer_id
  content:
    - name: custom_pattern
      pattern: "[A-Z]{3}-\\d{6}"
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify regions
	if len(config.Regions) != 2 {
		t.Errorf("Expected 2 regions, got %d", len(config.Regions))
	}
	if config.Regions[0] != Singapore || config.Regions[1] != Malaysia {
		t.Errorf("Regions not loaded correctly: %v", config.Regions)
	}

	// Verify strategy
	if config.Strategy != StrategyPartial {
		t.Errorf("Expected strategy=partial, got %s", config.Strategy)
	}

	// Verify explicit lists
	if len(config.AlwaysRedact) != 2 {
		t.Errorf("Expected 2 always_redact items, got %d", len(config.AlwaysRedact))
	}
	if len(config.NeverRedact) != 2 {
		t.Errorf("Expected 2 never_redact items, got %d", len(config.NeverRedact))
	}

	// Verify partial masking
	if config.PartialMaskChar != '*' {
		t.Errorf("Expected mask_char='*', got %c", config.PartialMaskChar)
	}
	if config.PartialKeepLeft != 2 {
		t.Errorf("Expected keep_left=2, got %d", config.PartialKeepLeft)
	}
	if config.PartialKeepRight != 4 {
		t.Errorf("Expected keep_right=4, got %d", config.PartialKeepRight)
	}

	// Verify hash salt
	if config.HashSalt != "test-salt" {
		t.Errorf("Expected hash_salt='test-salt', got %s", config.HashSalt)
	}

	// Verify max depth
	if config.MaxDepth != 15 {
		t.Errorf("Expected max_depth=15, got %d", config.MaxDepth)
	}

	// Verify custom patterns
	if len(config.CustomFieldPatterns) != 1 {
		t.Errorf("Expected 1 custom field pattern group, got %d", len(config.CustomFieldPatterns))
	}
	if len(config.CustomContentPatterns) != 1 {
		t.Errorf("Expected 1 custom content pattern, got %d", len(config.CustomContentPatterns))
	}
}

func TestLoadConfig_JSON(t *testing.T) {
	jsonContent := `{
  "regions": ["TH", "HK"],
  "strategy": "hash",
  "always_redact": ["secret"],
  "never_redact": ["id"],
  "hash_salt": "json-salt",
  "max_depth": 20
}`

	tmpFile := createTempFile(t, "config.json", jsonContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(config.Regions) != 2 {
		t.Errorf("Expected 2 regions, got %d", len(config.Regions))
	}
	if config.Strategy != StrategyHash {
		t.Errorf("Expected strategy=hash, got %s", config.Strategy)
	}
	if config.HashSalt != "json-salt" {
		t.Errorf("Expected hash_salt='json-salt', got %s", config.HashSalt)
	}
	if config.MaxDepth != 20 {
		t.Errorf("Expected max_depth=20, got %d", config.MaxDepth)
	}
}

func TestLoadConfig_AllRegions(t *testing.T) {
	yamlContent := `
regions:
  - SG
  - MY
  - AE
  - TH
  - HK
  - ID
  - PH
  - VN
  - KR
strategy: full
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(config.Regions) != 9 {
		t.Errorf("Expected 9 regions, got %d", len(config.Regions))
	}

	expectedRegions := []Region{Singapore, Malaysia, UAE, Thailand, HongKong, Indonesia, Philippines, Vietnam, SouthKorea}
	for i, expected := range expectedRegions {
		if config.Regions[i] != expected {
			t.Errorf("Region %d: expected %s, got %s", i, expected, config.Regions[i])
		}
	}
}

func TestLoadConfig_InvalidRegion(t *testing.T) {
	yamlContent := `
regions:
  - SG
  - INVALID
strategy: full
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid region, got nil")
	}
}

func TestLoadConfig_InvalidStrategy(t *testing.T) {
	yamlContent := `
regions:
  - SG
strategy: invalid_strategy
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid strategy, got nil")
	}
}

func TestLoadConfig_InvalidMaxDepth(t *testing.T) {
	yamlContent := `
regions:
  - SG
max_depth: 0
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid max_depth, got nil")
	}
}

func TestLoadConfig_InvalidMaskChar(t *testing.T) {
	yamlContent := `
regions:
  - SG
partial_masking:
  mask_char: "**"
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for multi-character mask_char, got nil")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for missing file, got nil")
	}
}

func TestLoadConfig_UnsupportedFormat(t *testing.T) {
	tmpFile := createTempFile(t, "config.txt", "some content")
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for unsupported format, got nil")
	}
}

func TestLoadConfig_Minimal(t *testing.T) {
	yamlContent := `
regions:
  - SG
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Should have defaults for unspecified values
	if config.Strategy != StrategyFull {
		t.Errorf("Expected default strategy=full, got %s", config.Strategy)
	}
	if config.MaxDepth != 10 {
		t.Errorf("Expected default max_depth=10, got %d", config.MaxDepth)
	}
	if config.PartialMaskChar != '*' {
		t.Errorf("Expected default mask_char='*', got %c", config.PartialMaskChar)
	}
}

func TestLoadConfig_EmptyRegions(t *testing.T) {
	yamlContent := `
regions: []
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for empty regions, got nil")
	}
}

func TestLoadConfig_CustomPatternCompilation(t *testing.T) {
	yamlContent := `
regions:
  - SG
custom_patterns:
  content:
    - name: test_pattern
      pattern: "[A-Z]{3}-\\d{3}"
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(config.CustomContentPatterns) != 1 {
		t.Errorf("Expected 1 custom pattern, got %d", len(config.CustomContentPatterns))
	}

	if config.CustomContentPatterns[0].Name != "test_pattern" {
		t.Errorf("Expected pattern name 'test_pattern', got '%s'", config.CustomContentPatterns[0].Name)
	}
}

func TestLoadConfig_InvalidCustomPattern(t *testing.T) {
	yamlContent := `
regions:
  - SG
custom_patterns:
  content:
    - name: bad_pattern
      pattern: "[invalid(regex"
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid regex pattern, got nil")
	}
}

func TestLoadConfig_CaseInsensitiveRegions(t *testing.T) {
	yamlContent := `
regions:
  - sg
  - my
  - th
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(config.Regions) != 3 {
		t.Errorf("Expected 3 regions, got %d", len(config.Regions))
	}
}

func TestLoadConfig_CaseInsensitiveStrategy(t *testing.T) {
	yamlContent := `
regions:
  - SG
strategy: PARTIAL
`

	tmpFile := createTempFile(t, "config.yaml", yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Strategy != StrategyPartial {
		t.Errorf("Expected strategy=partial, got %s", config.Strategy)
	}
}

// Helper function to create temporary config files for testing
func createTempFile(t *testing.T, name, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, name)

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	return tmpFile
}
