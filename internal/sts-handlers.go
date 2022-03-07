

package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	db "mt-iam/datastore"
	"mt-iam/logger"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"mt-iam/conf/openid"
	"mt-iam/internal/auth"
	xhttp "mt-iam/internal/http"

	iampolicy "github.com/minio/pkg/iam/policy"
	"github.com/minio/pkg/wildcard"
)

const (
	// STS API version.
	stsAPIVersion       = "2011-06-15"
	stsVersion          = "Version"
	stsAction           = "Action"
	stsPolicy           = "Policy"
	stsToken            = "Token"
	stsWebIdentityToken = "WebIdentityToken"
	stsDurationSeconds  = "DurationSeconds"
	stsLDAPUsername     = "LDAPUsername"
	stsLDAPPassword     = "LDAPPassword"

	// add tenant
	stsTenantName = "TenantName"
	stsAccessKey  = "AccessKey"
	stsSecretKey  = "SecretKey"
	stsSign       = "Sign"
	stsUserQuota  = "UserQuota"

	// STS API action constants
	clientGrants = "AssumeRoleWithClientGrants"
	webIdentity  = "AssumeRoleWithWebIdentity"
	ldapIdentity = "AssumeRoleWithLDAPIdentity"
	assumeRole   = "AssumeRole"

	stsRequestBodyLimit = 10 * (1 << 20) // 10 MiB

	// JWT claim keys
	expClaim = "exp"
	subClaim = "sub"
	issClaim = "iss"

	// JWT claim to check the parent user
	parentClaim = "parent"

	// LDAP claim keys
	ldapUser  = "ldapUser"
	ldapUserN = "ldapUsername"
)

func parseOpenIDParentUser(parentUser string) (userID string, err error) {
	if strings.HasPrefix(parentUser, "openid:") {
		tokens := strings.SplitN(strings.TrimPrefix(parentUser, "openid:"), ":", 2)
		if len(tokens) == 2 {
			return tokens[0], nil
		}
	}
	return "", errSkipFile
}

// stsAPIHandlers implements and provides http handlers for AWS STS API.
type stsAPIHandlers struct{}

// RegisterSTSRouter - registers AWS STS compatible APIs.
func RegisterSTSRouter(router *mux.Router) {
	// Initialize STS.
	sts := &stsAPIHandlers{}

	// STS Router
	stsRouter := router.NewRoute().PathPrefix(SlashSeparator).Subrouter()

	// add tenant
	stsRouter.Methods(http.MethodPost).Path("/v1"+"/add-tenant").HandlerFunc(httpTraceHdrs(sts.AddTenant)).Queries(stsTenantName, "{TenantName:.*}").Queries(stsAccessKey, "{AccessKey:.*}").Queries(stsSecretKey, "{SecretKey:.*}").Queries(stsUserQuota, "{UserQuota:.*}").Queries(stsSign, "{Sign:.*}")

	// Assume roles with no JWT, handles AssumeRole.
	stsRouter.Methods(http.MethodPost).MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		ctypeOk := wildcard.MatchSimple("application/x-www-form-urlencoded*", r.Header.Get(xhttp.ContentType))
		authOk := wildcard.MatchSimple(signV4Algorithm+"*", r.Header.Get(xhttp.Authorization))
		noQueries := len(r.URL.Query()) == 0
		return ctypeOk && authOk && noQueries
	}).HandlerFunc(httpTraceAll(sts.AssumeRole))

	//Assume roles with JWT handler, handles both ClientGrants and WebIdentity.
	stsRouter.Methods(http.MethodPost).MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		ctypeOk := wildcard.MatchSimple("application/x-www-form-urlencoded*", r.Header.Get(xhttp.ContentType))
		noQueries := len(r.URL.Query()) == 0
		return ctypeOk && noQueries
	}).HandlerFunc(httpTraceAll(sts.AssumeRoleWithSSO))

	// AssumeRoleWithClientGrants
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithClientGrants)).
		Queries(stsAction, clientGrants).
		Queries(stsVersion, stsAPIVersion).
		Queries(stsToken, "{Token:.*}")

	// AssumeRoleWithWebIdentity
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithWebIdentity)).
		Queries(stsAction, webIdentity).
		Queries(stsVersion, stsAPIVersion).
		Queries(stsWebIdentityToken, "{Token:.*}")

	// AssumeRoleWithLDAPIdentity
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithLDAPIdentity)).
		Queries(stsAction, ldapIdentity).
		Queries(stsVersion, stsAPIVersion).
		Queries(stsLDAPUsername, "{LDAPUsername:.*}").
		Queries(stsLDAPPassword, "{LDAPPassword:.*}")
}

func checkAssumeRoleAuth(ctx context.Context, r *http.Request) (user auth.Credentials, isErrCodeSTS bool, stsErr STSErrorCode) {
	switch getRequestAuthType(r) {
	default:
		return user, true, ErrSTSAccessDenied
	case authTypeSigned:
		s3Err := isReqAuthenticated(ctx, r, globalServerRegion, serviceSTS)
		if s3Err != ErrNone {
			return user, false, STSErrorCode(s3Err)
		}

		user, _, s3Err = getReqAccessKeyV4(r, globalServerRegion, serviceSTS)
		if s3Err != ErrNone {
			return user, false, STSErrorCode(s3Err)
		}

		// Temporary credentials or Service accounts cannot generate further temporary credentials.
		if user.IsTemp() || user.IsServiceAccount() {
			return user, true, ErrSTSAccessDenied
		}
	}

	// Session tokens are not allowed in STS AssumeRole requests.
	if getSessionToken(r) != "" {
		return user, true, ErrSTSAccessDenied
	}

	return user, true, ErrSTSNone
}

// AssumeRole - implementation of AWS STS API AssumeRole to get temporary
// credentials for regular users on Minio.
// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
func (sts *stsAPIHandlers) AssumeRole(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRole")

	user, isErrCodeSTS, stsErr := checkAssumeRoleAuth(ctx, r)
	if stsErr != ErrSTSNone {
		writeSTSErrorResponse(ctx, w, isErrCodeSTS, stsErr, nil)
		return
	}

	// TODO: code review
	// begin:
	// delete useless sts accounts and policies
	GlobalIAMSys.store.lock()
	for _, cred := range GlobalIAMSys.iamUsersMap {
		if cred.ParentUser == user.AccessKey {
			delete(GlobalIAMSys.iamUsersMap, cred.AccessKey)
			delete(GlobalIAMSys.iamUserPolicyMap, cred.AccessKey)
		}
	}
	GlobalIAMSys.store.unlock()
	// end

	if err := r.ParseForm(); err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, true, ErrSTSMissingParameter, fmt.Errorf("Invalid STS API version %s, expecting %s", r.Form.Get(stsVersion), stsAPIVersion))
		return
	}

	action := r.Form.Get(stsAction)
	switch action {
	case assumeRole:
	default:
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	ctx = newContext(r, w, action)
	//defer logger.AuditLog(ctx, w, r, nil)

	sessionPolicyStr := r.Form.Get(stsPolicy)
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
	// The plain text that you use for both inline and managed session
	// policies shouldn't exceed 2048 characters.
	if len(sessionPolicyStr) > 2048 {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Session policy shouldn't exceed 2048 characters"))
		return
	}

	if len(sessionPolicyStr) > 0 {
		sessionPolicy, err := iampolicy.ParseConfig(bytes.NewReader([]byte(sessionPolicyStr)))
		if err != nil {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
			return
		}

		// Version in policy must not be empty
		if sessionPolicy.Version == "" {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Version cannot be empty expecting '2012-10-17'"))
			return
		}
	}

	var err error
	m := make(map[string]interface{})
	m[expClaim], err = openid.GetDefaultExpiration(r.Form.Get(stsDurationSeconds))
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	//add by lyc begin
	mtAccount := db.GetMtAccount(user.AccessKey)
	if mtAccount == nil {
		logger.Error("database err: get mt_account failed")
		return
	} else if mtAccount.TenantId > 0 {
		tenantUser := db.GetAccountByUid(mtAccount.TenantId)
		if tenantUser == nil {
			logger.Error("database err: get mt_account failed")
			return
		} else {
			m["TenantId"] = tenantUser.Uid
			m["ParentUserId"] = mtAccount.ParentUser
		}
	} else {
		m["TenantId"] = mtAccount.Uid
		m["ParentUserId"] = mtAccount.ParentUser
	}
	//add by lyc end

	// check user's status
	dbCred := mtAccount.GetCredentialByAccount()
	if dbCred == nil {
		logger.Error("database err: get credential failed")
		return
	}
	if !dbCred.Status {
		writeSTSErrorResponse(ctx, w, true, ErrSTSAccessDenied, fmt.Errorf("Specified user is disabled"))
		return
	}

	policies, err := GlobalIAMSys.PolicyDBGet(user.AccessKey, false)
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}
	policyName := strings.Join(policies, ",")

	// This policy is the policy associated with the user
	// requesting for temporary credentials. The temporary
	// credentials will inherit the same policy requirements.
	m[iamPolicyClaimNameOpenID()] = policyName

	if len(sessionPolicyStr) > 0 {
		m[iampolicy.SessionPolicyName] = base64.StdEncoding.EncodeToString([]byte(sessionPolicyStr))
	}

	//secret := globalActiveCred.SecretKey
	secret := user.SecretKey
	//secret := user.AccessKey
	cred, err := auth.GetNewCredentialsWithMetadata(m, secret)
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInternalError, err)
		return
	}

	// Set the parent of the temporary access key, this is useful
	// in obtaining service accounts by this cred.
	cred.ParentUser = user.AccessKey

	// Set the newly generated credentials.
	if err = GlobalIAMSys.SetTempUser(cred.AccessKey, cred, policyName); err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInternalError, err)
		return
	}

	// Notify all other MinIO peers to reload temp users
	//for _, nerr := range globalNotificationSys.LoadUser(cred.AccessKey, true) {
	//	if nerr.Err != nil {
	//		logger.GetReqInfo(ctx).SetTags("peerAddress", nerr.Host.String())
	//		logger.LogIf(ctx, nerr.Err)
	//	}
	//}

	assumeRoleResponse := &AssumeRoleResponse{
		Result: AssumeRoleResult{
			Credentials: cred,
		},
	}

	assumeRoleResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
	writeSuccessResponseXML(w, encodeResponse(assumeRoleResponse))
}

func (sts *stsAPIHandlers) AssumeRoleWithSSO(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRoleSSOCommon")

	// Parse the incoming form data.
	if err := r.ParseForm(); err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, true, ErrSTSMissingParameter, fmt.Errorf("Invalid STS API version %s, expecting %s", r.Form.Get("Version"), stsAPIVersion))
		return
	}

	action := r.Form.Get(stsAction)
	switch action {
	case ldapIdentity:
		sts.AssumeRoleWithLDAPIdentity(w, r)
		return
	case clientGrants, webIdentity:
	default:
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	ctx = newContext(r, w, action)
	//defer logger.AuditLog(ctx, w, r, nil)

	if globalOpenIDValidators == nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSNotInitialized, errServerNotInitialized)
		return
	}

	v, err := globalOpenIDValidators.Get("jwt")
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	token := r.Form.Get(stsToken)
	if token == "" {
		token = r.Form.Get(stsWebIdentityToken)
	}

	m, err := v.Validate(token, r.Form.Get(stsDurationSeconds))
	if err != nil {
		switch err {
		case openid.ErrTokenExpired:
			switch action {
			case clientGrants:
				writeSTSErrorResponse(ctx, w, true, ErrSTSClientGrantsExpiredToken, err)
			case webIdentity:
				writeSTSErrorResponse(ctx, w, true, ErrSTSWebIdentityExpiredToken, err)
			}
			return
		case auth.ErrInvalidDuration:
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
			return
		}
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	var subFromToken string
	if v, ok := m[subClaim]; ok {
		subFromToken, _ = v.(string)
	}

	if subFromToken == "" {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, errors.New("STS JWT Token has `sub` claim missing, `sub` claim is mandatory"))
		return
	}

	var issFromToken string
	if v, ok := m[issClaim]; ok {
		issFromToken, _ = v.(string)
	}

	// JWT has requested a custom claim with policy value set.
	// This is a MinIO STS API specific value, this value should
	// be set and configured on your identity provider as part of
	// JWT custom claims.
	var policyName string
	policySet, ok := iampolicy.GetPoliciesFromClaims(m, iamPolicyClaimNameOpenID())
	policies := strings.Join(policySet.ToSlice(), ",")
	if ok {
		policyName = GlobalIAMSys.CurrentPolicies(policies)
	}

	if globalPolicyOPA == nil {
		if !ok {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue,
				fmt.Errorf("%s claim missing from the JWT token, credentials will not be generated", iamPolicyClaimNameOpenID()))
			return
		} else if policyName == "" {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue,
				fmt.Errorf("None of the given policies (`%s`) are defined, credentials will not be generated", policies))
			return
		}
	}
	m[iamPolicyClaimNameOpenID()] = policyName

	sessionPolicyStr := r.Form.Get(stsPolicy)
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
	// The plain text that you use for both inline and managed session
	// policies shouldn't exceed 2048 characters.
	if len(sessionPolicyStr) > 2048 {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Session policy should not exceed 2048 characters"))
		return
	}

	if len(sessionPolicyStr) > 0 {
		sessionPolicy, err := iampolicy.ParseConfig(bytes.NewReader([]byte(sessionPolicyStr)))
		if err != nil {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
			return
		}

		// Version in policy must not be empty
		if sessionPolicy.Version == "" {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Invalid session policy version"))
			return
		}

		m[iampolicy.SessionPolicyName] = base64.StdEncoding.EncodeToString([]byte(sessionPolicyStr))
	}

	secret := globalActiveCred.SecretKey
	cred, err := auth.GetNewCredentialsWithMetadata(m, secret)
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInternalError, err)
		return
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
	// claim is only considered stable when subject and iss are used together
	// this is to ensure that ParentUser doesn't change and we get to use
	// parentUser as per the requirements for service accounts for OpenID
	// based logins.
	cred.ParentUser = "openid:" + subFromToken + ":" + issFromToken

	// Set the newly generated credentials.
	if err = GlobalIAMSys.SetTempUser(cred.AccessKey, cred, policyName); err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInternalError, err)
		return
	}

	// Notify all other MinIO peers to reload temp users
	//for _, nerr := range globalNotificationSys.LoadUser(cred.AccessKey, true) {
	//	if nerr.Err != nil {
	//		logger.GetReqInfo(ctx).SetTags("peerAddress", nerr.Host.String())
	//		logger.LogIf(ctx, nerr.Err)
	//	}
	//}

	var encodedSuccessResponse []byte
	switch action {
	case clientGrants:
		clientGrantsResponse := &AssumeRoleWithClientGrantsResponse{
			Result: ClientGrantsResult{
				Credentials:      cred,
				SubjectFromToken: subFromToken,
			},
		}
		clientGrantsResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
		encodedSuccessResponse = encodeResponse(clientGrantsResponse)
	case webIdentity:
		webIdentityResponse := &AssumeRoleWithWebIdentityResponse{
			Result: WebIdentityResult{
				Credentials:                 cred,
				SubjectFromWebIdentityToken: subFromToken,
			},
		}
		webIdentityResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
		encodedSuccessResponse = encodeResponse(webIdentityResponse)
	}

	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// AssumeRoleWithWebIdentity - implementation of AWS STS API supporting OAuth2.0
// users from web identity provider such as Facebook, Google, or any OpenID
// Connect-compatible identity provider.
//
// Eg:-
//    $ curl https://minio:9000/?Action=AssumeRoleWithWebIdentity&WebIdentityToken=<jwt>
func (sts *stsAPIHandlers) AssumeRoleWithWebIdentity(w http.ResponseWriter, r *http.Request) {
	sts.AssumeRoleWithSSO(w, r)
}

// AssumeRoleWithClientGrants - implementation of AWS STS extension API supporting
// OAuth2.0 client credential grants.
//
// Eg:-
//    $ curl https://minio:9000/?Action=AssumeRoleWithClientGrants&Token=<jwt>
func (sts *stsAPIHandlers) AssumeRoleWithClientGrants(w http.ResponseWriter, r *http.Request) {
	sts.AssumeRoleWithSSO(w, r)
}

// AssumeRoleWithLDAPIdentity - implements user auth against LDAP server
func (sts *stsAPIHandlers) AssumeRoleWithLDAPIdentity(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRoleWithLDAPIdentity")

	//defer logger.AuditLog(ctx, w, r, nil, stsLDAPPassword)

	// Parse the incoming form data.
	if err := r.ParseForm(); err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, true, ErrSTSMissingParameter,
			fmt.Errorf("Invalid STS API version %s, expecting %s", r.Form.Get("Version"), stsAPIVersion))
		return
	}

	ldapUsername := r.Form.Get(stsLDAPUsername)
	ldapPassword := r.Form.Get(stsLDAPPassword)

	if ldapUsername == "" || ldapPassword == "" {
		writeSTSErrorResponse(ctx, w, true, ErrSTSMissingParameter, fmt.Errorf("LDAPUsername and LDAPPassword cannot be empty"))
		return
	}

	action := r.Form.Get(stsAction)
	switch action {
	case ldapIdentity:
	default:
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	sessionPolicyStr := r.Form.Get(stsPolicy)
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
	// The plain text that you use for both inline and managed session
	// policies shouldn't exceed 2048 characters.
	if len(sessionPolicyStr) > 2048 {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Session policy should not exceed 2048 characters"))
		return
	}

	if len(sessionPolicyStr) > 0 {
		sessionPolicy, err := iampolicy.ParseConfig(bytes.NewReader([]byte(sessionPolicyStr)))
		if err != nil {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
			return
		}

		// Version in policy must not be empty
		if sessionPolicy.Version == "" {
			writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, fmt.Errorf("Version needs to be specified in session policy"))
			return
		}
	}

	ldapUserDN, groupDistNames, err := globalLDAPConfig.Bind(ldapUsername, ldapPassword)
	if err != nil {
		err = fmt.Errorf("LDAP server error: %w", err)
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	// Check if this user or their groups have a policy applied.
	ldapPolicies, _ := GlobalIAMSys.PolicyDBGet(ldapUserDN, false, groupDistNames...)
	if len(ldapPolicies) == 0 && globalPolicyOPA == nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue,
			fmt.Errorf("expecting a policy to be set for user `%s` or one of their groups: `%s` - rejecting this request",
				ldapUserDN, strings.Join(groupDistNames, "`,`")))
		return
	}

	expiryDur, err := globalLDAPConfig.GetExpiryDuration(r.Form.Get(stsDurationSeconds))
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInvalidParameterValue, err)
		return
	}

	m := map[string]interface{}{
		expClaim:  UTCNow().Add(expiryDur).Unix(),
		ldapUser:  ldapUserDN,
		ldapUserN: ldapUsername,
	}

	if len(sessionPolicyStr) > 0 {
		m[iampolicy.SessionPolicyName] = base64.StdEncoding.EncodeToString([]byte(sessionPolicyStr))
	}

	secret := globalActiveCred.SecretKey
	cred, err := auth.GetNewCredentialsWithMetadata(m, secret)
	if err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInternalError, err)
		return
	}

	// Set the parent of the temporary access key, this is useful
	// in obtaining service accounts by this cred.
	cred.ParentUser = ldapUserDN

	// Set this value to LDAP groups, LDAP user can be part
	// of large number of groups
	cred.Groups = groupDistNames

	// Set the newly generated credentials, policyName is empty on purpose
	// LDAP policies are applied automatically using their ldapUser, ldapGroups
	// mapping.
	if err = GlobalIAMSys.SetTempUser(cred.AccessKey, cred, ""); err != nil {
		writeSTSErrorResponse(ctx, w, true, ErrSTSInternalError, err)
		return
	}

	// Notify all other MinIO peers to reload temp users
	//for _, nerr := range globalNotificationSys.LoadUser(cred.AccessKey, true) {
	//	if nerr.Err != nil {
	//		logger.GetReqInfo(ctx).SetTags("peerAddress", nerr.Host.String())
	//		logger.LogIf(ctx, nerr.Err)
	//	}
	//}

	ldapIdentityResponse := &AssumeRoleWithLDAPResponse{
		Result: LDAPIdentityResult{
			Credentials: cred,
		},
	}
	ldapIdentityResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
	encodedSuccessResponse := encodeResponse(ldapIdentityResponse)

	writeSuccessResponseXML(w, encodedSuccessResponse)
}

type Result struct {
	Success bool   `json:"success"` // 请求是否成功
	Data    string `json:"data"`    // 如果成功，这个就返回证书。失败就不做处理
	Msg     string `json:"msg"`     // 如果失败，这就会有内容。例如：用户名已经存在
}

// AddTenant 创建租户
func (sts *stsAPIHandlers) AddTenant(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AddTenant")
	//ctx := newContext(r, w, "AddTenant")
	vars := mux.Vars(r)
	tenantName := vars[stsTenantName]
	accessKey := vars[stsAccessKey]
	secretKey := vars[stsSecretKey]
	rsign := vars[stsSign]
	userQuotaStr := vars[stsUserQuota]

	// check sign
	newSign := requestSign(tenantName + accessKey + secretKey + userQuotaStr)
	//newSign := requestSign(tenantName + accessKey + secretKey )
	if newSign != rsign {
		res := &Result{
			Success: false,
			Msg:     errors.New("sign is invalid").Error(),
		}
		err := res.writeResponseJson(w)
		if err != nil {
			logger.Error("write response failed")
			return
		}
		return
	}

	// check tenantname and accesskey
	if tenantName == accessKey {
		res := &Result{
			Success: false,
			Msg:     errors.New("tenantName should be different with accesskey").Error(),
		}
		err := res.writeResponseJson(w)
		if err != nil {
			logger.Error("write response failed")
			return
		}
		return
	}

	//check quota
	quota, err := checkValidQuota(userQuotaStr)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAdminInvalidArgument), r.URL)
		if err != nil {
			return
		}
		return
	}

	// get tenant
	tenantUser := db.GetMtAccount(tenantName)
	if tenantUser == nil {
		logger.Error("database err: get mt_account failed")
		return
	}
	// get svc account
	tenantSvc := db.GetMtAccount(accessKey)
	if tenantSvc == nil {
		logger.Error("database err: get mt_account failed")
		return
	}
	// check if tenant or access key exists
	if tenantUser.Username != "" || tenantSvc.Username != "" {
		res := &Result{
			Success: false,
			Msg:     errors.New("tenant already exists").Error(),
		}
		err := res.writeResponseJson(w)
		if err != nil {
			logger.Error("write response failed")
			return
		}
		return
	}

	// gen tenant secret key
	readBytes := func(size int) (data []byte, err error) {
		data = make([]byte, size)
		var n int
		if n, err = rand.Read(data); err != nil {
			return nil, err
		} else if n != size {
			return nil, fmt.Errorf("Not enough data. Expected to read: %v bytes, got: %v bytes", size, n)
		}
		return data, nil
	}
	secret, err := readBytes(20)
	if err != nil {
		logger.Error("gen secret key failed")
		return
	}
	secretStr := hex.EncodeToString(secret)
	cred, err := auth.CreateCredentials(tenantName, secretStr)
	if err != nil {
		logger.Error("create credential failed")
		return
	}

	svcCred, err := GlobalIAMSys.CreateTenant(&cred, quota, func(claims map[string]interface{}) (c auth.Credentials, err error) {
		c, err = auth.CreateNewCredentialsWithMetadata(accessKey, secretKey, claims, cred.SecretKey)
		return c, err
	})
	if err != nil {
		res := &Result{
			Success: false,
			Msg:     err.Error(),
		}
		err = res.writeResponseJson(w)
		if err != nil {
			logger.Error("write response failed")
			return
		}
		return
	}

	addTenantResponse := &AddTenantResponse{
		svcCred,
	}
	buf, err := json.Marshal(addTenantResponse)
	if err != nil {
		logger.Error("json marshal failed")
		return
	}
	res := &Result{
		Success: true,
		Data:    string(buf),
	}
	resbuf, err := json.Marshal(res)
	if err != nil {
		logger.Error("json marshal failed")
		return
	}
	writeSuccessResponseJSON(w, resbuf)
}

func checkValidQuota(quota string) (int, error) {
	if quota == "" {
		return 0, errors.New("UserQuota require")
	}
	q, err := strconv.Atoi(quota)
	if err != nil {
		return 0, errors.New("UserQuota Invalid")
	}
	return q, nil

}

// for java api
func (re *Result) writeResponseJson(w http.ResponseWriter) error {
	marshal, err := json.Marshal(re)
	if err != nil {
		return err
	}
	_, err = w.Write(marshal)
	if err != nil {
		return err
	}
	w.(http.Flusher).Flush()
	return nil
}
