package main

import (
	"fmt"
	"github.com/go-openapi/loads"
	"github.com/gorilla/mux"
	"github.com/minio/console/restapi"
	"github.com/minio/console/restapi/operations"
	"github.com/minio/pkg/env"
	internal2 "mt-iam/internal"
	http2 "mt-iam/internal/http"
	"mt-iam/pkg/config"
	datastore2 "mt-iam/pkg/datastore"
	"mt-iam/pkg/logger"
	"net/http"
	"os"
)

func main() {
	fmt.Println("server start")
	err := config.InitConfig()
	if err != nil {
		panic(err)
		return
	}

	//init logger
	level := config.GetString("logger.level")
	if level == "" {
		level = "info"
	}
	logger.InitLogger(level)

	datastore2.InitDB()
	internal2.Start()

	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	addr := ":10001"

	// register router
	internal2.RegisterIamRouter(router)

	internal2.RegisterAdminRouter(router)
	internal2.RegisterSTSRouter(router)

	//包装的handler，处理定义之外的请求
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle request using passed handler.
		//正常请求
		router.ServeHTTP(w, r)
	})

	sever := http2.NewServer([]string{addr}, wrappedHandler, nil)
	logger.Infof("api listening at: %s", addr)
	go sever.Start()

	globalOSSignalCh := make(chan os.Signal, 1)
	consoleSrv, err2 := initConsoleServer()
	if err2 != nil {
		logger.FatalIf("Unable to initialize console service", err2)
	}
	go func() {
		<-globalOSSignalCh
		consoleSrv.Shutdown()
	}()
	consoleSrv.Serve()

}

const consolePrefix = "CONSOLE_"

func initConsoleServer() (*restapi.Server, error) {
	// unset all console_ environment variables.
	for _, cenv := range env.List(consolePrefix) {
		os.Unsetenv(cenv)
	}

	// enable all console environment variables
	minioConfigToConsoleFeatures()

	swaggerSpec, err := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
	if err != nil {
		return nil, err
	}

	console := operations.NewConsoleAPI(swaggerSpec)
	console.Logger = func(format  string, data ...interface{}) {
		logger.Infof(format, data)
	}

	server := restapi.NewServer(console)
	// register all APIs
	server.ConfigureAPI()

	consolePort := 13333

	server.Host = ""
	server.Port = consolePort
	restapi.Port = "13333"
	restapi.Hostname = "localhost"

	return server, nil
}

func minioConfigToConsoleFeatures() {
	os.Setenv("CONSOLE_MINIO_SERVER", "http://localhost:10001")
	os.Setenv("CONSOLE_TYPE_IAM", "iam")
}
