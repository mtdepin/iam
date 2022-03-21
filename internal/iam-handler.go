package internal

import (
	"encoding/json"
	"mt-iam/internal/auth"
	xhttp "mt-iam/internal/http"
	"mt-iam/pkg/logger"
	"net/http"
	"strings"
)

// ClaimInfoHandler - GET /minio/admin/v3/info
// ----------
// Get claim information
func (a iamAPIHandlers) ClaimInfoHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("==> ClaimInfoHandler")
	printReqInfo(r)
	ctx := newContext(r, w, "ServerInfo")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	//把前缀去掉
	r.RequestURI = strings.Replace(r.RequestURI, "/claim", "", 1)

	atype := getRequestAuthType(r)
	ar := AuthResult{
		authType: atype,
		Cred:     auth.Credentials{},
		Owner:    false,
		Claims:   nil,
	}
	if atype != authTypeUnknown {
		cred, owner, claims, s3Err := MustGetClaimsFromToken(r)
		if s3Err != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
			return
		}
		cred.SecretKey = ""
		cred.SessionToken = ""
		ar.Cred = cred
		ar.Owner = owner
		ar.Claims = claims

		if v , ok := getValue(claims, Ctx_TenantId) ; ok {
			ar.TenantId = v
		}

		if v , ok := getValue(claims, Ctx_ParentUserId) ; ok {
			ar.ParentUserId = v
		}
	}
	result, _ := json.Marshal(ar)
	logger.Infof("result: %s", result)

	writeSuccessResponseJSON(w, result)
}

func getValue(claims map[string]interface{}, key string) (int, bool) {
	value, ok := claims[key]
	if ok {
		if na, ok := value.(float64); ok {
			return int(na), ok
		}
	}
	return 0, false
}

// AuthInfoHandler - GET /minio/admin/v3/info
// ----------
// Get auth information
func (a iamAPIHandlers) AuthInfoHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("==> AuthInfoHandler")
	printReqInfo(r)
	r.RequestURI = strings.Replace(r.RequestURI, "/auth", "", 1)
	r.URL.Path = strings.Replace(r.URL.Path, "/auth", "", 1)

	//r.Host = "192.168.1.135:9000"
	IsAllowed(w, r)
}

// ValidateSignatureHandler - GET /minio/admin/v3/info
// ----------
// ValidateSignatureHandler
func (a iamAPIHandlers) ValidateSignatureHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("==> ValidateSignatureHandler")
	printReqInfo(r)
	r.RequestURI = strings.Replace(r.RequestURI, "/validateSignature", "", 1)
	r.URL.Path = strings.Replace(r.URL.Path, "/validateSignature", "", 1)

	ValidateSignature(w, r)
}

func printReqInfo(r *http.Request) {
	authToken := r.Header.Get(xhttp.Authorization)
	logger.Infof("request RequestURI: %s", r.RequestURI)
	logger.Infof("request authToken: %s", authToken)

}
