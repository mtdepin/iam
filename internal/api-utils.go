package internal

import (
	"crypto/sha1"
	"fmt"
	"github.com/minio/madmin-go"
	"net/http"
	"strings"
)

const (
	//密钥
	Key = "mtyw123*7^$#@"
)

func requestSign(input string) string {
	method := sha1.New()
	method.Write([]byte(input))
	bs := method.Sum([]byte(Key))
	result := fmt.Sprintf("%x", bs)
	return result
}

// If none of the http routes match respond with appropriate errors
func errorResponseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	version := extractAPIVersion(r)
	switch {
	case strings.HasPrefix(r.URL.Path, peerRESTPrefix):
		desc := fmt.Sprintf("Server expects 'peer' API version '%s', instead found '%s' - *rolling upgrade is not allowed* - please make sure all servers are running the same MinIO version (%s)", peerRESTVersion, version, "")
		writeErrorResponseString(r.Context(), w, APIError{
			Code:           "XMinioPeerVersionMismatch",
			Description:    desc,
			HTTPStatusCode: http.StatusUpgradeRequired,
		}, r.URL)
	case strings.HasPrefix(r.URL.Path, storageRESTPrefix):
		desc := fmt.Sprintf("Server expects 'storage' API version '%s', instead found '%s' - *rolling upgrade is not allowed* - please make sure all servers are running the same MinIO version (%s)", storageRESTVersion, version, "")
		writeErrorResponseString(r.Context(), w, APIError{
			Code:           "XMinioStorageVersionMismatch",
			Description:    desc,
			HTTPStatusCode: http.StatusUpgradeRequired,
		}, r.URL)
	//case strings.HasPrefix(r.URL.Path, lockRESTPrefix):
	//	desc := fmt.Sprintf("Server expects 'lock' API version '%s', instead found '%s' - *rolling upgrade is not allowed* - please make sure all servers are running the same MinIO version (%s)", lockRESTVersion, version, ReleaseTag)
	//	writeErrorResponseString(r.Context(), w, APIError{
	//		Code:           "XMinioLockVersionMismatch",
	//		Description:    desc,
	//		HTTPStatusCode: http.StatusUpgradeRequired,
	//	}, r.URL)
	case strings.HasPrefix(r.URL.Path, adminPathPrefix):
		var desc string
		if version == "v1" {
			desc = fmt.Sprintf("Server expects client requests with 'admin' API version '%s', found '%s', please upgrade the client to latest releases", madmin.AdminAPIVersion, version)
		} else if version == madmin.AdminAPIVersion {
			desc = fmt.Sprintf("This 'admin' API is not supported by server in '%s'", getMinioMode())
		} else {
			desc = fmt.Sprintf("Unexpected client 'admin' API version found '%s', expected '%s', please downgrade the client to older releases", version, madmin.AdminAPIVersion)
		}
		writeErrorResponseJSON(r.Context(), w, APIError{
			Code:           "XMinioAdminVersionMismatch",
			Description:    desc,
			HTTPStatusCode: http.StatusUpgradeRequired,
		}, r.URL)
	default:
		writeErrorResponse(r.Context(), w, APIError{
			Code: "BadRequest",
			Description: fmt.Sprintf("An error occurred when parsing the HTTP request %s at '%s'",
				r.Method, r.URL.Path),
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)
	}

}
