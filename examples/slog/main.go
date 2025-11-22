package main

import (
	"log/slog"
	"os"

	"github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

func main() {
	// Create sanitizer with default config (all regions)
	s := sanitizer.NewDefault()

	// Configure slog with JSON handler
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Example 1: Sanitize a map with PII
	logger.Info("=== Example 1: User Data ===")
	userData := map[string]any{
		"fullName": "John Doe",
		"email":    "john.doe@example.com",
		"phone":    "+6591234567",
		"nric":     "S1234567A",
		"orderId":  "ORD-123456",
		"amount":   150.50,
	}
	logger.Info("Processing user", "user", s.SlogValue(userData))

	// Example 2: Sanitize nested data
	logger.Info("\n=== Example 2: Nested Transaction Data ===")
	transaction := map[string]any{
		"transactionId": "TXN-789",
		"user": map[string]any{
			"fullName":      "Jane Smith",
			"email":         "jane@example.com",
			"accountNumber": "1234567890",
		},
		"payment": map[string]any{
			"amount":   99.99,
			"currency": "SGD",
			"memo":     "Payment for services to Jane Smith",
		},
	}
	logger.Info("Transaction processed", s.SlogAttr("transaction", transaction))

	// Example 3: Use SlogString for individual fields
	logger.Info("\n=== Example 3: Individual Fields ===")
	logger.Info("User login",
		s.SlogString("email", "user@example.com"),
		slog.String("userId", "USR-123"),
		slog.String("ip", "192.168.1.100"),
	)

	// Example 4: Use SlogGroup
	logger.Info("\n=== Example 4: Grouped Fields ===")
	logger.Info("Payment processed",
		s.SlogGroup("customer",
			"fullName", "Bob Johnson",
			"email", "bob@example.com",
		),
		slog.String("orderId", "ORD-999"),
		slog.Float64("amount", 250.00),
	)

	// Example 5: Regional patterns
	logger.Info("\n=== Example 5: Regional PII Patterns ===")
	regionalData := map[string]any{
		"singapore_nric":  "S1234567A",
		"malaysia_mykad":  "901230-14-5678",
		"uae_emirates_id": "784-2020-1234567-1",
		"thailand_id":     "1-2345-67890-12-3",
		"hongkong_hkid":   "A123456(7)",
		"safe_product_id": "PROD-12345",
	}
	logger.Info("Regional data", "data", s.SlogValue(regionalData))

	// Example 6: Custom configuration - Permissive for logs
	logger.Info("\n=== Example 6: Custom Config (Permissive for Logs) ===")
	logSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithRedact("description", "memo", "reference"). // Extra fields
			WithPreserve("orderId", "productId"),           // Preserve business IDs
	)

	logData := map[string]any{
		"orderId":     "ORD-123",
		"productId":   "PROD-456",
		"description": "Payment to merchant ABC",
		"email":       "customer@example.com",
		"amount":      100.00,
	}
	logger.Info("Log data", "data", logSanitizer.SlogValue(logData))

	// Example 7: Custom configuration - Strict for UI
	logger.Info("\n=== Example 7: Custom Config (Strict for UI) ===")
	uiSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithRedact(
				"fullName", "firstName", "lastName",
				"email", "emailAddress",
				"accountNumber", "bankAccount",
			).
			WithPreserve(
				"orderId", "transactionId", "currency",
			),
	)

	uiData := map[string]any{
		"orderId":       "ORD-123",
		"transactionId": "TXN-456",
		"fullName":      "Alice Wong",
		"email":         "alice@example.com",
		"currency":      "SGD",
		"amount":        75.50,
	}
	logger.Info("UI data", "data", uiSanitizer.SlogValue(uiData))

	// Example 8: Partial masking strategy
	logger.Info("\n=== Example 8: Partial Masking ===")
	partialSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithStrategy(sanitizer.StrategyPartial).
			WithPartialMasking('*', 0, 4), // Show last 4 characters
	)

	partialData := map[string]any{
		"email":      "john.doe@example.com",
		"creditCard": "4532-1234-5678-9010",
		"orderId":    "ORD-789",
	}
	logger.Info("Partial masking", "data", partialSanitizer.SlogValue(partialData))
}
