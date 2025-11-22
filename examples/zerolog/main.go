package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/vsemashko/go-pii-sanitizer/sanitizer"
)

func main() {
	// Create sanitizer with default config (all regions)
	s := sanitizer.NewDefault()

	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Example 1: Sanitize a map with PII
	logger.Info().Msg("=== Example 1: User Data ===")
	userData := map[string]interface{}{
		"fullName": "John Doe",
		"email":    "john.doe@example.com",
		"phone":    "+6591234567",
		"nric":     "S1234567A",
		"orderId":  "ORD-123456",
		"amount":   150.50,
	}
	logger.Info().Object("user", s.ZerologObject(userData)).Msg("Processing user")

	// Example 2: Sanitize nested data
	logger.Info().Msg("=== Example 2: Nested Transaction Data ===")
	transaction := map[string]interface{}{
		"transactionId": "TXN-789",
		"user": map[string]interface{}{
			"fullName":      "Jane Smith",
			"email":         "jane@example.com",
			"accountNumber": "1234567890",
		},
		"payment": map[string]interface{}{
			"amount":   99.99,
			"currency": "SGD",
			"memo":     "Payment for services to Jane Smith",
		},
	}
	logger.Info().Object("transaction", s.ZerologObject(transaction)).Msg("Transaction processed")

	// Example 3: Use ZerologString for individual fields
	logger.Info().Msg("=== Example 3: Individual Fields ===")
	email := "user@example.com"
	key, value := s.ZerologString("email", email)
	logger.Info().
		Str(key, value).
		Str("userId", "USR-123").
		Str("ip", "192.168.1.100").
		Msg("User login")

	// Example 4: Multiple sanitized objects
	logger.Info().Msg("=== Example 4: Multiple Objects ===")
	customer := map[string]interface{}{
		"fullName": "Bob Johnson",
		"email":    "bob@example.com",
	}
	order := map[string]interface{}{
		"orderId": "ORD-999",
		"amount":  250.00,
	}
	logger.Info().
		Object("customer", s.ZerologObject(customer)).
		Object("order", s.ZerologObject(order)).
		Msg("Order created")

	// Example 5: Regional patterns
	logger.Info().Msg("=== Example 5: Regional PII Patterns ===")
	regionalData := map[string]interface{}{
		"singapore_nric":   "S1234567A",
		"malaysia_mykad":   "901230-14-5678",
		"uae_emirates_id":  "784-2020-1234567-1",
		"thailand_id":      "1-2345-67890-12-3",
		"hongkong_hkid":    "A123456(7)",
		"safe_product_id":  "PROD-12345",
	}
	logger.Info().Object("data", s.ZerologObject(regionalData)).Msg("Regional data")

	// Example 6: Slices and arrays
	logger.Info().Msg("=== Example 6: Slices of Data ===")
	users := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"email":   "user1@example.com",
				"orderId": "ORD-1",
			},
			map[string]interface{}{
				"email":   "user2@example.com",
				"orderId": "ORD-2",
			},
		},
	}
	logger.Info().Object("data", s.ZerologObject(users)).Msg("User list")

	// Example 7: Custom configuration - Permissive for logs
	logger.Info().Msg("=== Example 7: Custom Config (Permissive for Logs) ===")
	logSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithRedact("description", "memo", "reference").
			WithPreserve("orderId", "productId"),
	)

	logData := map[string]interface{}{
		"orderId":     "ORD-123",
		"productId":   "PROD-456",
		"description": "Payment to merchant ABC",
		"email":       "customer@example.com",
		"amount":      100.00,
	}
	logger.Info().Object("data", logSanitizer.ZerologObject(logData)).Msg("Log data")

	// Example 8: Custom configuration - Strict for UI
	logger.Info().Msg("=== Example 8: Custom Config (Strict for UI) ===")
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

	uiData := map[string]interface{}{
		"orderId":       "ORD-123",
		"transactionId": "TXN-456",
		"fullName":      "Alice Wong",
		"email":         "alice@example.com",
		"currency":      "SGD",
		"amount":        75.50,
	}
	logger.Info().Object("data", uiSanitizer.ZerologObject(uiData)).Msg("UI data")

	// Example 9: Partial masking strategy
	logger.Info().Msg("=== Example 9: Partial Masking ===")
	partialSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithStrategy(sanitizer.StrategyPartial).
			WithPartialMasking('*', 0, 4),
	)

	partialData := map[string]interface{}{
		"email":      "john.doe@example.com",
		"creditCard": "4532-1234-5678-9010",
		"orderId":    "ORD-789",
	}
	logger.Info().Object("data", partialSanitizer.ZerologObject(partialData)).Msg("Partial masking")

	// Example 10: Hash strategy
	logger.Info().Msg("=== Example 10: Hash Strategy ===")
	hashSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithStrategy(sanitizer.StrategyHash),
	)

	hashData := map[string]interface{}{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}
	logger.Info().Object("data", hashSanitizer.ZerologObject(hashData)).Msg("Hash strategy")

	// Example 11: Pretty console output
	logger.Info().Msg("=== Example 11: Pretty Console Output ===")
	prettyLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()

	prettyData := map[string]interface{}{
		"email":   "john@example.com",
		"name":    "John Doe",
		"orderId": "ORD-555",
	}
	prettyLogger.Info().Object("data", s.ZerologObject(prettyData)).Msg("Pretty output example")
}
