package main

import (
	"flag"
	"log"
	"os"

	"gitlab.apk-group.net/siem/backend/asset-discovery/api/handlers/http"
	"gitlab.apk-group.net/siem/backend/asset-discovery/app"
	"gitlab.apk-group.net/siem/backend/asset-discovery/config"
)

var configPath = flag.String("config", "config.json", "service configuration file")

func main() {
	flag.Parse()
	if v := os.Getenv("CONFIG_PATH"); len(v) > 0 {
		*configPath = v
	}
	config := config.MustReadConfig(*configPath)
	AppContainer := app.NewMustApp(config)
	log.Fatal(http.Run(AppContainer, config.Server))
}
