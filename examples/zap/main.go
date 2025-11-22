package main

import (
	"github.com/vsemashko/go-pii-sanitizer/sanitizer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// Create sanitizer with default config (all regions)
	s := sanitizer.NewDefault()

	// Configure zap with JSON encoder
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, _ := config.Build()
	defer logger.Sync()

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
	logger.Info("Processing user", zap.Object("user", s.ZapObject(userData)))

	// Example 2: Sanitize nested data
	logger.Info("=== Example 2: Nested Transaction Data ===")
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
	logger.Info("Transaction processed", s.ZapField("transaction", transaction))

	// Example 3: Use ZapString for individual fields
	logger.Info("=== Example 3: Individual Fields ===")
	logger.Info("User login",
		s.ZapString("email", "user@example.com"),
		zap.String("userId", "USR-123"),
		zap.String("ip", "192.168.1.100"),
	)

	// Example 4: Multiple sanitized objects
	logger.Info("=== Example 4: Multiple Objects ===")
	customer := map[string]any{
		"fullName": "Bob Johnson",
		"email":    "bob@example.com",
	}
	order := map[string]any{
		"orderId": "ORD-999",
		"amount":  250.00,
	}
	logger.Info("Order created",
		zap.Object("customer", s.ZapObject(customer)),
		zap.Object("order", s.ZapObject(order)),
	)

	// Example 5: Regional patterns
	logger.Info("=== Example 5: Regional PII Patterns ===")
	regionalData := map[string]any{
		"singapore_nric":  "S1234567A",
		"malaysia_mykad":  "901230-14-5678",
		"uae_emirates_id": "784-2020-1234567-1",
		"thailand_id":     "1-2345-67890-12-3",
		"hongkong_hkid":   "A123456(7)",
		"safe_product_id": "PROD-12345",
	}
	logger.Info("Regional data", zap.Object("data", s.ZapObject(regionalData)))

	// Example 6: Slices and arrays
	logger.Info("=== Example 6: Slices of Data ===")
	users := map[string]any{
		"users": []any{
			map[string]any{
				"email":   "user1@example.com",
				"orderId": "ORD-1",
			},
			map[string]any{
				"email":   "user2@example.com",
				"orderId": "ORD-2",
			},
		},
	}
	logger.Info("User list", zap.Object("data", s.ZapObject(users)))

	// Example 7: Custom configuration - Permissive for logs
	logger.Info("=== Example 7: Custom Config (Permissive for Logs) ===")
	logSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithRedact("description", "memo", "reference").
			WithPreserve("orderId", "productId"),
	)

	logData := map[string]any{
		"orderId":     "ORD-123",
		"productId":   "PROD-456",
		"description": "Payment to merchant ABC",
		"email":       "customer@example.com",
		"amount":      100.00,
	}
	logger.Info("Log data", zap.Object("data", logSanitizer.ZapObject(logData)))

	// Example 8: Custom configuration - Strict for UI
	logger.Info("=== Example 8: Custom Config (Strict for UI) ===")
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
	logger.Info("UI data", zap.Object("data", uiSanitizer.ZapObject(uiData)))

	// Example 9: Partial masking strategy
	logger.Info("=== Example 9: Partial Masking ===")
	partialSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithStrategy(sanitizer.StrategyPartial).
			WithPartialMasking('*', 0, 4),
	)

	partialData := map[string]any{
		"email":      "john.doe@example.com",
		"creditCard": "4532-1234-5678-9010",
		"orderId":    "ORD-789",
	}
	logger.Info("Partial masking", zap.Object("data", partialSanitizer.ZapObject(partialData)))

	// Example 10: Hash strategy
	logger.Info("=== Example 10: Hash Strategy ===")
	hashSanitizer := sanitizer.New(
		sanitizer.NewDefaultConfig().
			WithStrategy(sanitizer.StrategyHash),
	)

	hashData := map[string]any{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}
	logger.Info("Hash strategy", zap.Object("data", hashSanitizer.ZapObject(hashData)))
}
