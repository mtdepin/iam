package api

import (
	"github.com/gin-gonic/gin"
	"mt-iam/service"
)

func InitRouter() *gin.Engine {
	r := gin.New()
	r.POST("/iam/isAllowed", service.IsAllowed)
	//r.POST("/iam/getTokenClaim", service.MustGetClaimsFromToken)
	r.Run(":10000")
	return r
}
