package main

import (
	"fmt"
	"mt-iam/api"
)

func main() {
	fmt.Println("server start")
	api.InitRouter()
}
