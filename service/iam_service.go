package service

import (
	"github.com/gin-gonic/gin"
	iampolicy "github.com/minio/pkg/iam/policy"
	"mt-iam/internal"
	"net/http"
)

func IsAllowed(c *gin.Context) {
	var sy *internal.IAMSys
	var args *iampolicy.Args
	c.BindJSON(&args)
	allowed := sy.IsAllowed(*args)
	c.JSON(http.StatusOK, allowed)
}
