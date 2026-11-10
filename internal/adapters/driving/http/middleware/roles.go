package middleware

import (
	"github.com/efangly/smtrack-authentication/internal/adapters/driving/http/dto"
	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/gofiber/fiber/v3"
)

// TiersGuard lets a request through only when the caller's tier is one of
// allowed. Roles are not checked here: this service decides by tier alone (ADR 0006).
func TiersGuard(allowed ...domain.Tier) fiber.Handler {
	return func(c fiber.Ctx) error {
		user := c.Locals("user")
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(dto.FailResponse("Unauthorized"))
		}

		payload, ok := user.(*domain.Actor)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(dto.FailResponse("Invalid user context"))
		}

		// If no tiers specified, allow all authenticated users
		if len(allowed) == 0 {
			return c.Next()
		}

		for _, tier := range allowed {
			if tier == payload.Tier {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(dto.FailResponse("You do not have the required role"))
	}
}
