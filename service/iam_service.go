package service

import (
	"github.com/gin-gonic/gin"
	iampolicy "github.com/minio/pkg/iam/policy"
	"mt-iam/internal"
	"net/http"
)

func IsAllowed(c *gin.Context) {

	var args *iampolicy.Args
	c.BindJSON(&args)
	allowed := internal.GlobalIAMSys.IsAllowed(*args)
	c.JSON(http.StatusOK, allowed)
}
func MustGetClaimsFromToken(c *gin.Context) {
	token := internal.MustGetClaimsFromToken(c.Request)
	c.JSON(http.StatusOK, token)
}
