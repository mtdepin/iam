package internal

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	db "mt-iam/pkg/datastore"
	"mt-iam/pkg/logger"
	"net/http"

	"mt-iam/internal/auth"
	"mt-iam/internal/etag"
	"mt-iam/internal/hash"
	xhttp "mt-iam/internal/http"
	xjwt "mt-iam/internal/jwt"
	"strings"

	"github.com/minio/pkg/bucket/policy"
	iampolicy "github.com/minio/pkg/iam/policy"
)

// Verify if request has JWT.
func isRequestJWT(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(xhttp.Authorization), jwtAlgorithm)
}

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(xhttp.Authorization), signV4Algorithm)
}

// Verify if request has AWS Signature Version '2'.
func isRequestSignatureV2(r *http.Request) bool {
	return (!strings.HasPrefix(r.Header.Get(xhttp.Authorization), signV4Algorithm) &&
		strings.HasPrefix(r.Header.Get(xhttp.Authorization), signV2Algorithm))
}

// Verify if request has AWS PreSign Version '4'.
func isRequestPresignedSignatureV4(r *http.Request) bool {
	_, ok := r.URL.Query()[xhttp.AmzCredential]
	return ok
}

// Verify request has AWS PreSign Version '2'.
func isRequestPresignedSignatureV2(r *http.Request) bool {
	_, ok := r.URL.Query()[xhttp.AmzAccessKeyID]
	return ok
}

// Verify if request has AWS Post policy Signature Version '4'.
func isRequestPostPolicySignatureV4(r *http.Request) bool {
	return strings.Contains(r.Header.Get(xhttp.ContentType), "multipart/form-data") &&
		r.Method == http.MethodPost
}

// Verify if the request has AWS Streaming Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestSignStreamingV4(r *http.Request) bool {
	return r.Header.Get(xhttp.AmzContentSha256) == streamingContentSHA256 &&
		r.Method == http.MethodPut
}

// Authorization type.
type authType int

// List of all supported auth types.
const (
	authTypeUnknown authType = iota
	authTypeAnonymous
	authTypePresigned
	authTypePresignedV2
	authTypePostPolicy
	authTypeStreamingSigned
	authTypeSigned
	authTypeSignedV2
	authTypeJWT
	authTypeSTS
)

// Get request authentication type.
func getRequestAuthType(r *http.Request) authType {
	if isRequestSignatureV2(r) {
		return authTypeSignedV2
	} else if isRequestPresignedSignatureV2(r) {
		return authTypePresignedV2
	} else if isRequestSignStreamingV4(r) {
		return authTypeStreamingSigned
	} else if isRequestSignatureV4(r) {
		return authTypeSigned
	} else if isRequestPresignedSignatureV4(r) {
		return authTypePresigned
	} else if isRequestJWT(r) {
		return authTypeJWT
	} else if isRequestPostPolicySignatureV4(r) {
		return authTypePostPolicy
	} else if _, ok := r.URL.Query()[xhttp.Action]; ok {
		return authTypeSTS
	} else if _, ok := r.Header[xhttp.Authorization]; !ok {
		return authTypeAnonymous
	}
	return authTypeUnknown
}

type validateSignatureResult struct {
	Cred   auth.Credentials
	Owner  bool
	Claims map[string]interface{}
}

func ValidateSignature(w http.ResponseWriter, r *http.Request) {
	cred, claims, owner, err := validateAdminSignature(context.TODO(), r, "")
	if err != ErrNone {
		//writeErrorResponseJSON(context.Background(), w, toAPIErrorCode(context.TODO(), err), r.URL)

	}
	vr := validateSignatureResult{
		Cred:   cred,
		Owner:  owner,
		Claims: claims,
	}

	result, _ := json.Marshal(vr)
	writeSuccessResponseJSON(w, result)
}

func validateAdminSignature(ctx context.Context, r *http.Request, region string) (auth.Credentials, map[string]interface{}, bool, APIErrorCode) {
	var cred auth.Credentials
	var owner bool
	s3Err := ErrAccessDenied
	//if _, ok := r.Header[xhttp.AmzContentSha256]; ok
	//	getRequestAuthType(r) == authTypeSigned && !skipContentSha256Cksum(r) {
	//	// We only support admin credentials to access admin APIs.
	//	cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
	//	if s3Err != ErrNone {
	//		return cred, nil, owner, s3Err
	//	}
	//
	//	// we only support V4 (no presign) with auth body
	//	s3Err = isReqAuthenticated(ctx, r, region, serviceS3)
	//}
	//if s3Err != ErrNone {
	//	reqInfo := (&logger.ReqInfo{}).AppendTags("requestHeaders", dumpRequest(r))
	//	ctx := logger.SetReqInfo(ctx, reqInfo)
	//	logger.LogIf(ctx, errors.New(getAPIError(s3Err).Description), logger.Application)
	//	return cred, nil, owner, s3Err
	//}

	if _, ok := r.Header[xhttp.AmzContentSha256]; ok {
		switch getRequestAuthType(r) {
		case authTypeUnknown:
			return auth.Credentials{}, nil, false, ErrSignatureVersionNotSupported
		case authTypeSignedV2, authTypePresignedV2:
			cred, owner, s3Err = getReqAccessKeyV2(r)
		case authTypeStreamingSigned, authTypePresigned, authTypeSigned:
			region := globalServerRegion
			cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
			// we only support V4 (no presign) with auth body
			//s3Err = isReqAuthenticated(ctx, r, region, serviceS3)
			//case authTypeSigned:
			//	if !skipContentSha256Cksum(r) {
			//		cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
			//		if s3Err != ErrNone {
			//			return cred, nil, owner, s3Err
			//		}
			//		// we only support V4 (no presign) with auth body
			//		s3Err = isReqAuthenticated(ctx, r, region, serviceS3)
			//	}
		}
	}

	if s3Err != ErrNone {
		reqInfo := (&logger.ReqInfo{}).AppendTags("requestHeaders", dumpRequest(r))
		ctx := logger.SetReqInfo(ctx, reqInfo)
		logger.LogIf(ctx, errors.New(getAPIError(s3Err).Description), logger.Application)
		return cred, nil, owner, s3Err
	}

	claims, s3Err := checkClaimsFromToken(r, cred)
	if s3Err != ErrNone {
		return cred, nil, owner, s3Err
	}

	return cred, claims, owner, ErrNone
}

// checkAdminRequestAuth checks for authentication and authorization for the incoming
// request. It only accepts V2 and V4 requests. Presigned, JWT and anonymous requests
// are automatically rejected.
func checkAdminRequestAuth(ctx context.Context, r *http.Request, action iampolicy.AdminAction, region string) (auth.Credentials, APIErrorCode) {
	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, region)
	if s3Err != ErrNone {
		return cred, s3Err
	}
	if GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Groups:          cred.Groups,
		Action:          iampolicy.Action(action),
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
		IsOwner:         owner,
		Claims:          claims,
	}) {
		// Request is allowed return the appropriate access key.
		return cred, ErrNone
	}

	return cred, ErrAccessDenied
}

// Fetch the security token set by the client.
func getSessionToken(r *http.Request) (token string) {
	token = r.Header.Get(xhttp.AmzSecurityToken)
	if token != "" {
		return token
	}
	return r.URL.Query().Get(xhttp.AmzSecurityToken)
}
func MustGetClaimsFromToken(r *http.Request) map[string]interface{} {
	return mustGetClaimsFromToken(r)
}

// Fetch claims in the security token returned by the client, doesn't return
// errors - upon errors the returned claims map will be empty.
func mustGetClaimsFromToken(r *http.Request) map[string]interface{} {
	//change by lyc begin
	var cred auth.Credentials
	if isRequestSignatureV2(r) {
		c, _, s3Err := getReqAccessKeyV2(r)
		if s3Err != ErrNone {
			return nil
		}
		cred = c

		claims, _ := checkClaimsFromToken(r, cred)
		return claims
	} else if isRequestSignatureV4(r) {
		c, _, s3Err := getReqAccessKeyV4(r, "", serviceS3)
		if s3Err != ErrNone {
			return nil
		}
		cred = c
		claims, _ := checkClaimsFromToken(r, cred)
		return claims
	}

	claims, _ := getClaimsFromToken(getSessionToken(r), cred)
	//change by lyc end
	return claims
}

// Fetch claims in the security token returned by the client.
//change by lyc :增加一个参数 cred auth.Credentials
func getClaimsFromToken(token string, cred auth.Credentials) (map[string]interface{}, error) {
	if token == "" {
		claims := xjwt.NewMapClaims()
		return claims.Map(), nil
	}

	// JWT token for x-amz-security-token is signed with admin
	// secret key, temporary credentials become invalid if
	// server admin credentials change. This is done to ensure
	// that clients cannot decode the token using the temp
	// secret keys and generate an entirely new claim by essentially
	// hijacking the policies. We need to make sure that this is
	// based an admin credential such that token cannot be decoded
	// on the client side and is treated like an opaque value.

	//claims, err := auth.ExtractClaims(token, globalActiveCred.SecretKey)
	pUser := db.GetMtAccount(cred.ParentUser)
	claims, err := auth.ExtractClaims(token, pUser.Password)
	if err != nil {
		return nil, errAuthentication
	}

	// If OPA is set, return without any further checks.
	if globalPolicyOPA != nil {
		return claims.Map(), nil
	}

	// Check if a session policy is set. If so, decode it here.
	sp, spok := claims.Lookup(iampolicy.SessionPolicyName)
	if spok {
		// Looks like subpolicy is set and is a string, if set then its
		// base64 encoded, decode it. Decoding fails reject such
		// requests.
		spBytes, err := base64.StdEncoding.DecodeString(sp)
		if err != nil {
			// Base64 decoding fails, we should log to indicate
			// something is malforming the request sent by client.
			logger.LogIf(GlobalContext, err, logger.Application)
			return nil, errAuthentication
		}
		claims.MapClaims[iampolicy.SessionPolicyName] = string(spBytes)
	}

	// If LDAP claim key is set, return here.
	if _, ok := claims.MapClaims[ldapUser]; ok {
		return claims.Map(), nil
	}

	// Session token must have a policy, reject requests without policy
	// claim.
	_, pokOpenID := claims.MapClaims[iamPolicyClaimNameOpenID()]
	_, pokSA := claims.MapClaims[iamPolicyClaimNameSA()]
	if !pokOpenID && !pokSA {
		return nil, errAuthentication
	}

	return claims.Map(), nil
}

// Fetch claims in the security token returned by the client and validate the token.
func checkClaimsFromToken(r *http.Request, cred auth.Credentials) (map[string]interface{}, APIErrorCode) {
	token := getSessionToken(r)
	if token != "" && cred.AccessKey == "" {
		return nil, ErrNoAccessKey
	}
	if cred.IsServiceAccount() && token == "" {
		token = cred.SessionToken
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(cred.SessionToken)) != 1 {
		return nil, ErrInvalidToken
	}
	//change by lyc begin
	claims, err := getClaimsFromToken(token, cred)
	//change by lyc end
	if err != nil {
		return nil, toAPIErrorCode(r.Context(), err)
	}
	return claims, ErrNone
}

// Check request auth type verifies the incoming http request
// - validates the request signature
// - validates the policy action if anonymous tests bucket policies if any,
//   for authenticated requests validates IAM policies.
// returns APIErrorCode if any to be replied to the client.
func checkRequestAuthType(ctx context.Context, r *http.Request, action policy.Action, bucketName, objectName string) (s3Err APIErrorCode) {
	_, _, s3Err = checkRequestAuthTypeCredential(ctx, r, action, bucketName, objectName)
	return s3Err
}

// Check request auth type verifies the incoming http request
// - validates the request signature
// - validates the policy action if anonymous tests bucket policies if any,
//   for authenticated requests validates IAM policies.
// returns APIErrorCode if any to be replied to the client.
// Additionally returns the accessKey used in the request, and if this request is by an admin.
// 原IAM验证逻辑：
// 1.根据authType验证请求，若为身份认证，则需要验证签名；否则，为匿名请求，证书设置为空；
// 2.若用户请求行为为创建桶，则单独处理locationConstraint；
// 3.若用户为匿名请求，则验证桶策略；
// 4.验证用户IAM策略，是否支持用户当前行为；
// 5.若用户请求为ListBucketVersionsAction，需要再验证用户IAM策略是否支持ListBucketAction。
//
// 修改后验证逻辑（对象匿名请求需调用checkRequestAuthTypeAnonymous进行验证）：
// 1.根据authType验证请求，若为身份认证，则需要验证签名；否则，为匿名请求，证书设置为空；
// 2.若用户请求行为为创建桶，则单独处理locationConstraint；
// 3.验证IAM策略和桶策略，是否支持用户当前行为；
// 4.若用户请求为ListBucketVersionsAction，需要再验证用户IAM策略、桶策略是否支持ListBucketAction。
func checkRequestAuthTypeCredential(ctx context.Context, r *http.Request, action policy.Action, bucketName, objectName string) (cred auth.Credentials, owner bool, s3Err APIErrorCode) {
	switch getRequestAuthType(r) {
	case authTypeUnknown, authTypeStreamingSigned:
		return cred, owner, ErrSignatureVersionNotSupported
	case authTypePresignedV2, authTypeSignedV2:
		if s3Err = isReqAuthenticatedV2(r); s3Err != ErrNone {
			return cred, owner, s3Err
		}
		cred, owner, s3Err = getReqAccessKeyV2(r)
	case authTypeSigned, authTypePresigned:
		region := globalServerRegion
		switch action {
		case policy.GetBucketLocationAction, policy.ListAllMyBucketsAction:
			region = ""
		}
		if s3Err = isReqAuthenticated(ctx, r, region, serviceS3); s3Err != ErrNone {
			return cred, owner, s3Err
		}
		cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
	}
	if s3Err != ErrNone {
		return cred, owner, s3Err
	}

	var claims map[string]interface{}
	claims, s3Err = checkClaimsFromToken(r, cred)
	if s3Err != ErrNone {
		return cred, owner, s3Err
	}

	//add by lyc begin
	//获取对应账号的租户信息
	//mtAccount := db.GetMtAccount(cred.ParentUser)
	//if mtAccount != nil && mtAccount.TenantId > 0 {
	//	tenant := db.GetAccountByUid(mtAccount.TenantId)
	//	r.Header.Set("tenantId", fmt.Sprintf("%d", tenant.Uid))
	//} else {
	//	r.Header.Set("tenantId", fmt.Sprintf("%d", mtAccount.Uid))
	//}
	//add by lyc end

	if action == policy.CreateBucketAction {
		// To extract region from XML in request body, get copy of request body.
		payload, err := ioutil.ReadAll(io.LimitReader(r.Body, maxLocationConstraintSize))
		if err != nil {
			logger.LogIf(ctx, err, logger.Application)
			return cred, owner, ErrMalformedXML
		}

		// Populate payload to extract location constraint.
		r.Body = ioutil.NopCloser(bytes.NewReader(payload))

		// Populate payload again to handle it in HTTP handler.
		r.Body = ioutil.NopCloser(bytes.NewReader(payload))
	}
	if cred.AccessKey != "" {
		logger.GetReqInfo(ctx).AccessKey = cred.AccessKey
	}

	//if action != policy.ListAllMyBucketsAction && cred.AccessKey == "" {
	//	// Anonymous checks are not meant for ListBuckets action
	//	if globalPolicySys.IsAllowed(policy.Args{
	//		AccountName:     cred.AccessKey,
	//		Action:          action,
	//		BucketName:      bucketName,
	//		ConditionValues: getConditionValues(r, locationConstraint, "", nil),
	//		IsOwner:         false,
	//		ObjectName:      objectName,
	//	}) {
	//		// Request is allowed return the appropriate access key.
	//		return cred, owner, ErrNone
	//	}
	//
	//	if action == policy.ListBucketVersionsAction {
	//		// In AWS S3 s3:ListBucket permission is same as s3:ListBucketVersions permission
	//		// verify as a fallback.
	//		if globalPolicySys.IsAllowed(policy.Args{
	//			AccountName:     cred.AccessKey,
	//			Action:          policy.ListBucketAction,
	//			BucketName:      bucketName,
	//			ConditionValues: getConditionValues(r, locationConstraint, "", nil),
	//			IsOwner:         false,
	//			ObjectName:      objectName,
	//		}) {
	//			// Request is allowed return the appropriate access key.
	//			return cred, owner, ErrNone
	//		}
	//	}
	//
	//	return cred, owner, ErrAccessDenied
	//}

	// 验证桶策略和IAM策略
	var iamPolicy, bucketPolicy bool

	// 验证IAM策略
	iamPolicy = GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Groups:          cred.Groups,
		Action:          iampolicy.Action(action),
		BucketName:      bucketName,
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
		ObjectName:      objectName,
		IsOwner:         owner,
		Claims:          claims,
	})

	if action == policy.ListBucketVersionsAction {
		// In AWS S3 s3:ListBucket permission is same as s3:ListBucketVersions permission
		// verify as a fallback.
		iamPolicy = GlobalIAMSys.IsAllowed(iampolicy.Args{
			AccountName:     cred.AccessKey,
			Groups:          cred.Groups,
			Action:          iampolicy.ListBucketAction,
			BucketName:      bucketName,
			ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
			ObjectName:      objectName,
			IsOwner:         owner,
			Claims:          claims,
		})
	}

	// 若IAM和桶策略任一验证通过，则允许访问
	if iamPolicy || bucketPolicy {
		return cred, owner, ErrNone
	}

	return cred, owner, ErrAccessDenied
}

// Verify if request has valid AWS Signature Version '2'.
func isReqAuthenticatedV2(r *http.Request) (s3Error APIErrorCode) {
	if isRequestSignatureV2(r) {
		return doesSignV2Match(r)
	}
	return doesPresignV2SignatureMatch(r)
}

func reqSignatureV4Verify(r *http.Request, region string, stype serviceType) (s3Error APIErrorCode) {
	sha256sum := getContentSha256Cksum(r, stype)
	switch {
	case isRequestSignatureV4(r):
		return doesSignatureMatch(sha256sum, r, region, stype)
	case isRequestPresignedSignatureV4(r):
		return doesPresignedSignatureMatch(sha256sum, r, region, stype)
	default:
		return ErrAccessDenied
	}
}

// Verify if request has valid AWS Signature Version '4'.
func isReqAuthenticated(ctx context.Context, r *http.Request, region string, stype serviceType) (s3Error APIErrorCode) {
	if errCode := reqSignatureV4Verify(r, region, stype); errCode != ErrNone {
		return errCode
	}

	clientETag, err := etag.FromContentMD5(r.Header)
	if err != nil {
		return ErrInvalidDigest
	}

	// Extract either 'X-Amz-Content-Sha256' header or 'X-Amz-Content-Sha256' query parameter (if V4 presigned)
	// Do not verify 'X-Amz-Content-Sha256' if skipSHA256.
	var contentSHA256 []byte
	if skipSHA256 := skipContentSha256Cksum(r); !skipSHA256 && isRequestPresignedSignatureV4(r) {
		if sha256Sum, ok := r.URL.Query()[xhttp.AmzContentSha256]; ok && len(sha256Sum) > 0 {
			contentSHA256, err = hex.DecodeString(sha256Sum[0])
			if err != nil {
				return ErrContentSHA256Mismatch
			}
		}
	} else if _, ok := r.Header[xhttp.AmzContentSha256]; !skipSHA256 && ok {
		contentSHA256, err = hex.DecodeString(r.Header.Get(xhttp.AmzContentSha256))
		if err != nil || len(contentSHA256) == 0 {
			return ErrContentSHA256Mismatch
		}
	}

	// Verify 'Content-Md5' and/or 'X-Amz-Content-Sha256' if present.
	// The verification happens implicit during reading.
	reader, err := hash.NewReader(r.Body, -1, clientETag.String(), hex.EncodeToString(contentSHA256), -1)
	if err != nil {
		return toAPIErrorCode(ctx, err)
	}
	r.Body = reader
	return ErrNone
}

// List of all support S3 auth types.
var supportedS3AuthTypes = map[authType]struct{}{
	authTypeAnonymous:       {},
	authTypePresigned:       {},
	authTypePresignedV2:     {},
	authTypeSigned:          {},
	authTypeSignedV2:        {},
	authTypePostPolicy:      {},
	authTypeStreamingSigned: {},
}

// Validate if the authType is valid and supported.
func isSupportedS3AuthType(aType authType) bool {
	_, ok := supportedS3AuthTypes[aType]
	return ok
}
