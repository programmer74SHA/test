package http

import (
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/jwt"
	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/context"

	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func newAuthMiddleware(secret []byte) fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey:  jwtware.SigningKey{Key: secret},
		Claims:      &jwt.UserClaims{},
		TokenLookup: "header:Authorization",
		SuccessHandler: func(ctx *fiber.Ctx) error {
			userClaims := userClaims(ctx)
			if userClaims == nil {
				return fiber.ErrUnauthorized
			}

			logger := context.GetLogger(ctx.UserContext())
			context.SetLogger(ctx.UserContext(), logger.With("user_id", userClaims.UserID))

			return ctx.Next()
		},
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			return fiber.NewError(fiber.StatusUnauthorized, err.Error())
		},
		AuthScheme: "Bearer",
	})
}

func setUserContext(c *fiber.Ctx) error {
	c.SetUserContext(context.NewAppContext(c.UserContext(), context.WithLogger(logger.NewLogger())))
	return c.Next()
}

func setTransaction(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tx := db.Begin()

		context.SetDB(c.UserContext(), tx, true)

		err := c.Next()

		if c.Response().StatusCode() >= 300 {
			return context.Rollback(c.UserContext())
		}

		if err := context.CommitOrRollback(c.UserContext(), true); err != nil {
			return err
		}

		return err
	}
}
