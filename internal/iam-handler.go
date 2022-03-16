package internal

import (
	"encoding/json"
	http2 "mt-iam/internal/http"
	"mt-iam/pkg/logger"
	"net/http"
	"strings"
)

// ClaimInfoHandler - GET /minio/admin/v3/info
// ----------
// Get claim information
func (a iamAPIHandlers) ClaimInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ServerInfo")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	//把前缀去掉
	r.RequestURI = strings.Replace(r.RequestURI, "/claim", "", 1)
	token := MustGetClaimsFromToken(r)
	// todo 处理异常结果返回
	if token != nil {
		//写入返回结果
		w.Header().Set(http2.ContentType, "content-type/json")
		w.WriteHeader(200)
		result, _ := json.Marshal(token)
		_, _ = w.Write(result)
		w.(http.Flusher).Flush()
		return
	}
	w.Header().Set(http2.ContentType, "content-type/json")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(""))
	w.(http.Flusher).Flush()

	// Reply with storage information (across nodes in a
	// distributed setup) as json.
	writeSuccessResponseJSON(w, []byte{})
}

// AuthInfoHandler - GET /minio/admin/v3/info
// ----------
// Get auth information
func (a iamAPIHandlers) AuthInfoHandler(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.Replace(r.RequestURI, "/auth", "", 1)
	r.URL.Path = strings.Replace(r.URL.Path, "/auth", "", 1)

	//r.Host = "192.168.1.135:9000"
	IsAllowed(w, r)
}

// ValidateSignatureHandler - GET /minio/admin/v3/info
// ----------
// ValidateSignatureHandler
func (a iamAPIHandlers) ValidateSignatureHandler(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.Replace(r.RequestURI, "/validateSignature", "", 1)
	r.URL.Path = strings.Replace(r.URL.Path, "/validateSignature", "", 1)

	ValidateSignature(w, r)
}
