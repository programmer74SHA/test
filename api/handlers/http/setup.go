package http

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

func Run(appContainer app.AppContainer, cfg config.ServerConfig) error {
	router := fiber.New()

	api := router.Group("/api/v1", setUserContext)

	registerAuthAPI(appContainer, cfg, api)

	registerScannerAPI(appContainer, api.Group("/scanners", newAuthMiddleware([]byte(cfg.Secret))))

	return router.Listen(fmt.Sprintf(":%d", cfg.HttpPort))
}

func registerAuthAPI(appContainer app.AppContainer, cfg config.ServerConfig, router fiber.Router) {
	userSvcGetter := userServiceGetter(appContainer, cfg)
	router.Post("/sign-up", setTransaction(appContainer.DB()), SignUp(userSvcGetter))
	router.Post("/sign-in", setTransaction(appContainer.DB()), SignIn(userSvcGetter, cfg))
}

func registerScannerAPI(appContainer app.AppContainer, cfg config.ServerConfig, router fiber.Router) {
	scannerSvGetter := scannerServiceGetter(appContainer, cfg)
	router.Post("/add-scanner", setTransaction(appContainer.DB()), CreateScanner(scannerSvGetter))
	router.Post("/get-scanner", setTransaction(appContainer.DB()), GetScanner(scannerSvGetter))
	router.Post("/update-scanner", setTransaction(appContainer.DB()), UpdateScanner(scannerSvGetter))
	router.Post("/delete-scanner", setTransaction(appContainer.DB()), DeleteScanner(scannerSvGetter))

}
