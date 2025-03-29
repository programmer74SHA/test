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

	// registerScannerAPI(appContainer, api.Group("/scanners", newAuthMiddleware([]byte(cfg.Secret))))
	registerScannerAPI(appContainer, api.Group("/scanners"))

	return router.Listen(fmt.Sprintf(":%d", cfg.HttpPort))
}

func registerAuthAPI(appContainer app.AppContainer, cfg config.ServerConfig, router fiber.Router) {
	userSvcGetter := userServiceGetter(appContainer, cfg)
	router.Post("/sign-up", setTransaction(appContainer.DB()), SignUp(userSvcGetter))
	router.Post("/sign-in", setTransaction(appContainer.DB()), SignIn(userSvcGetter, cfg))
}

func registerScannerAPI(appContainer app.AppContainer, router fiber.Router) {
	scannerSvcGetter := scannerServiceGetter(appContainer)
	router.Post("/", setTransaction(appContainer.DB()), CreateScanner(scannerSvcGetter))
	router.Get("/:id", GetScanner(scannerSvcGetter))
	router.Get("/", ListScanners(scannerSvcGetter))
	router.Put("/:id", setTransaction(appContainer.DB()), UpdateScanner(scannerSvcGetter))
	router.Delete("/:id", setTransaction(appContainer.DB()), DeleteScanner(scannerSvcGetter))

	router.Post("/batch-delete", setTransaction(appContainer.DB()), DeleteScanners(scannerSvcGetter))
	router.Post("/batch-enabled", setTransaction(appContainer.DB()), BatchUpdateScannersEnabled(scannerSvcGetter))

}
