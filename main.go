package main

import (
	"fmt"
	"mt-iam/api"
	config "mt-iam/conf"
	"mt-iam/datastore"
)

func main() {
	fmt.Println("server start")
	config.InitConfig()
	datastore.InitDB()
	api.InitRouter()
}
