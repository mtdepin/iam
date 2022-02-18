package api

import (
	"github.com/gin-gonic/gin"
	"mt-iam/service"
)

func InitRouter() *gin.Engine {
	r := gin.New()
	r.POST("iam", service.IsAllowed)
	r.Run(":10000")
	return r
}
