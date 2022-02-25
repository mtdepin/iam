package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"mt-iam/api"
	config "mt-iam/conf"
	"mt-iam/datastore"
	"mt-iam/internal"
	xhttp "mt-iam/internal/http"
)

func main() {
	fmt.Println("server start")
	config.InitConfig()
	datastore.InitDB()
	// Initialize router. `SkipClean(true)` stops gorilla/mux from
	// normalizing URL path minio/minio#3256
	// avoid URL path encoding minio/minio#8950
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	addr := ":10001"

	// Enable STS router if etcd is enabled.
	internal.RegisterSTSRouter(router)
	sever := xhttp.NewServer([]string{addr}, router, nil)
	go func() {
		sever.Start()
	}()
	api.InitRouter()
}
