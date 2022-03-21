package internal

import (
	"net/http"

	"github.com/gorilla/mux"
)

const (
	AdminAPIVersion     = "v1"
	iamPathPrefix       = SlashSeparator + "iam"
	iamAPIVersion       = AdminAPIVersion
	iamAPIVersionPrefix = SlashSeparator + iamAPIVersion
)

// iamAPIHandlers provides HTTP handlers for MinIO admin API.
type iamAPIHandlers struct{}

// RegisterIamRouter - Add handler functions for each service REST API routes.
func RegisterIamRouter(router *mux.Router) {
	iamAPI := iamAPIHandlers{}
	// Admin router
	iamRouter := router.PathPrefix("/claim").Subrouter()
	iamRouter.Methods(http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead).HandlerFunc(httpTraceAll(iamAPI.ClaimInfoHandler))

	iamRouter = router.PathPrefix("/auth").Subrouter()
	iamRouter.Methods(http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete).HandlerFunc(httpTraceAll(iamAPI.AuthInfoHandler))

	iamRouter = router.PathPrefix("/validateSignature").Subrouter()
	iamRouter.Methods(http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete).HandlerFunc(httpTraceAll(iamAPI.ValidateSignatureHandler))

}
