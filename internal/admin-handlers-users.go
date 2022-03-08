package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	"github.com/minio/kes"
	"github.com/minio/madmin-go"
	"github.com/minio/pkg/bucket/policy"
	iampolicy "github.com/minio/pkg/iam/policy"
	"io"
	"io/ioutil"
	"mt-iam/internal/auth"
	"mt-iam/logger"
	"net/http"
)

func toAdminAPIErr(ctx context.Context, err error) APIError {
	if err == nil {
		return noError
	}

	var apiErr APIError
	switch e := err.(type) {
	case AdminError:
		apiErr = APIError{
			Code:           e.Code,
			Description:    e.Message,
			HTTPStatusCode: e.StatusCode,
		}
	default:
		switch {
		case errors.Is(err, errIAMActionNotAllowed):
			apiErr = APIError{
				Code:           "XMinioIAMActionNotAllowed",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusForbidden,
			}
		case errors.Is(err, errIAMNotInitialized):
			apiErr = APIError{
				Code:           "XMinioIAMNotInitialized",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusServiceUnavailable,
			}
		case errors.Is(err, kes.ErrKeyExists):
			apiErr = APIError{
				Code:           "XMinioKMSKeyExists",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusConflict,
			}

		// Tier admin API errors
		case errors.Is(err, madmin.ErrTierNameEmpty):
			apiErr = APIError{
				Code:           "XMinioAdminTierNameEmpty",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		case errors.Is(err, madmin.ErrTierInvalidConfig):
			apiErr = APIError{
				Code:           "XMinioAdminTierInvalidConfig",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		case errors.Is(err, madmin.ErrTierInvalidConfigVersion):
			apiErr = APIError{
				Code:           "XMinioAdminTierInvalidConfigVersion",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		}
	}
	return apiErr
}

// AccountInfoHandler returns usage
func (a adminAPIHandlers) AccountInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AccountInfo")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred, _, _, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	// Set prefix value for "s3:prefix" policy conditionals.
	r.Header.Set("prefix", "")

	// Set delimiter value for "s3:delimiter" policy conditionals.
	r.Header.Set("delimiter", SlashSeparator)

	// Check if we are asked to return prefix usage
	//enablePrefixUsage := r.URL.Query().Get("prefix-usage") == "true"

	var err error

	accountName := cred.AccessKey
	var policies []string
	switch GlobalIAMSys.usersSysType {
	case MinIOUsersSysType:
		policies, err = GlobalIAMSys.PolicyDBGet(accountName, false)
	case LDAPUsersSysType:
		parentUser := accountName
		if cred.ParentUser != "" {
			parentUser = cred.ParentUser
		}
		policies, err = GlobalIAMSys.PolicyDBGet(parentUser, false, cred.Groups...)
	default:
		err = errors.New("should never happen")
	}
	if err != nil {
		logger.LogIf(ctx, err)
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	buf, err := json.MarshalIndent(GlobalIAMSys.GetCombinedPolicy(policies...), "", " ")
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	acctInfo := madmin.AccountInfo{
		AccountName: accountName,
		//Server:      objectAPI.BackendInfo(),
		Server: madmin.BackendInfo{},
		Policy: buf,
	}

	usageInfoJSON, err := json.Marshal(acctInfo)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, usageInfoJSON)
}

// As per AWS S3 specification, 20KiB policy JSON data is allowed.
const maxBucketPolicySize = 20 * humanize.KiByte

// Admin API errors
const (
	AdminUpdateUnexpectedFailure = "XMinioAdminUpdateUnexpectedFailure"
	AdminUpdateURLNotReachable   = "XMinioAdminUpdateURLNotReachable"
	AdminUpdateApplyFailure      = "XMinioAdminUpdateApplyFailure"
)

func validateAdminUsersReq(ctx context.Context, w http.ResponseWriter, r *http.Request, action iampolicy.AdminAction) auth.Credentials {
	var cred auth.Credentials
	var adminAPIErr APIErrorCode

	// Validate request signature.
	cred, adminAPIErr = checkAdminRequestAuth(ctx, r, action, "")
	if adminAPIErr != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(adminAPIErr), r.URL)
		return cred
	}

	return cred
}

// RemoveUser - DELETE /minio/admin/v3/remove-user?accessKey=<access_key>
func (a adminAPIHandlers) RemoveUser(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "RemoveUser")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	_ = validateAdminUsersReq(ctx, w, r, iampolicy.DeleteUserAdminAction)

	vars := mux.Vars(r)
	accessKey := vars["accessKey"]

	ok, _, err := GlobalIAMSys.IsTempUser(accessKey)
	if err != nil {
		if err != errNoSuchUser {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
	}
	if ok {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, errIAMActionNotAllowed), r.URL)
		return
	}

	if err = GlobalIAMSys.DeleteUser(accessKey); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

}

// ListUsers - GET /minio/admin/v3/list-users?bucket={bucket}
func (a adminAPIHandlers) ListBucketUsers(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListBucketUsers")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.ListUsersAdminAction)

	bucket := mux.Vars(r)["bucket"]

	password := cred.SecretKey

	allCredentials, err := GlobalIAMSys.ListBucketUsers(bucket)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	data, err := json.Marshal(allCredentials)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	econfigData, err := madmin.EncryptData(password, data)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, econfigData)
}

// ListUsers - GET /minio/admin/v3/list-users
func (a adminAPIHandlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListUsers")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.ListUsersAdminAction)

	password := cred.SecretKey

	//allCredentials, err := GlobalIAMSys.ListUsers()
	allCredentials, err := GlobalIAMSys.ListUsers(cred.ParentUser)

	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	data, err := json.Marshal(allCredentials)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	econfigData, err := madmin.EncryptData(password, data)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, econfigData)
}

// GetUserInfo - GET /minio/admin/v3/user-info
func (a adminAPIHandlers) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetUserInfo")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	name := vars["accessKey"]

	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	accessKey := cred.ParentUser
	if accessKey == "" {
		accessKey = cred.AccessKey
	}

	// For temporary credentials always
	// the temporary credentials to check
	// policy without implicit permissions.
	//if cred.IsTemp() && cred.ParentUser == globalActiveCred.AccessKey {
	//	accessKey = cred.AccessKey
	//}

	implicitPerm := name == accessKey
	if !implicitPerm {
		if !GlobalIAMSys.IsAllowed(iampolicy.Args{
			AccountName:     accessKey,
			Groups:          cred.Groups,
			Action:          iampolicy.GetUserAdminAction,
			ConditionValues: getConditionValues(r, "", accessKey, claims),
			IsOwner:         owner,
			Claims:          claims,
		}) {
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	userInfo, err := GlobalIAMSys.GetUserInfo(name)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	data, err := json.Marshal(userInfo)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, data)
}

// UpdateGroupMembers - PUT /minio/admin/v3/update-group-members
func (a adminAPIHandlers) UpdateGroupMembers(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "UpdateGroupMembers")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.AddUserToGroupAdminAction)

	defer r.Body.Close()
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	var updReq madmin.GroupAddRemove
	err = json.Unmarshal(data, &updReq)
	if err != nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	if updReq.IsRemove {
		err = GlobalIAMSys.RemoveUsersFromGroup(cred.ParentUser, updReq.Group, updReq.Members)
	} else {
		err = GlobalIAMSys.AddUsersToGroup(cred.ParentUser, updReq.Group, updReq.Members)
	}

	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

}

// GetGroup - /minio/admin/v3/group?group=mygroup1
func (a adminAPIHandlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetGroup")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	_ = validateAdminUsersReq(ctx, w, r, iampolicy.GetGroupAdminAction)

	vars := mux.Vars(r)
	group := vars["group"]

	gdesc, err := GlobalIAMSys.GetGroupDescription(group)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	body, err := json.Marshal(gdesc)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, body)
}

// ListGroups - GET /minio/admin/v3/groups
func (a adminAPIHandlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListGroups")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.ListGroupsAdminAction)

	groups, err := GlobalIAMSys.ListGroups(cred.ParentUser)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	body, err := json.Marshal(groups)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, body)
}

// SetGroupStatus - PUT /minio/admin/v3/set-group-status?group=mygroup1&status=enabled
func (a adminAPIHandlers) SetGroupStatus(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "SetGroupStatus")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.EnableGroupAdminAction)

	vars := mux.Vars(r)
	group := vars["group"]
	status := vars["status"]

	var err error
	if status == statusEnabled {
		err = GlobalIAMSys.SetGroupStatus(cred.ParentUser, group, true)
	} else if status == statusDisabled {
		err = GlobalIAMSys.SetGroupStatus(cred.ParentUser, group, false)
	} else {
		err = errInvalidArgument
	}
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
}

// SetUserStatus - PUT /minio/admin/v3/set-user-status?accessKey=<access_key>&status=[enabled|disabled]
func (a adminAPIHandlers) SetUserStatus(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "SetUserStatus")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.EnableUserAdminAction)

	vars := mux.Vars(r)
	accessKey := vars["accessKey"]
	status := vars["status"]

	// This API is not allowed to lookup accessKey user status
	//if accessKey == globalActiveCred.AccessKey {
	//	writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
	//	return
	//}

	if err := GlobalIAMSys.SetUserStatus(cred.ParentUser, accessKey, madmin.AccountStatus(status)); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
}

// AddUser - PUT /minio/admin/v3/add-user?accessKey=<access_key>
func (a adminAPIHandlers) AddUser(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AddUser")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	accessKey := vars["accessKey"]

	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	// Not allowed to add a user with same access key as root credential
	//if owner && accessKey == cred.AccessKey {
	//	writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAddUserInvalidArgument), r.URL)
	//	return
	//}

	if (cred.IsTemp() || cred.IsServiceAccount()) && cred.ParentUser == accessKey {
		// Incoming access key matches parent user then we should
		// reject password change requests.
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAddUserInvalidArgument), r.URL)
		return
	}

	implicitPerm := accessKey == cred.AccessKey
	if !implicitPerm {
		parentUser := cred.ParentUser
		if parentUser == "" {
			parentUser = cred.AccessKey
		}
		// For temporary credentials always
		// the temporary credentials to check
		// policy without implicit permissions.
		//if cred.IsTemp() && cred.ParentUser == globalActiveCred.AccessKey {
		//	parentUser = cred.AccessKey
		//}
		if !GlobalIAMSys.IsAllowed(iampolicy.Args{
			AccountName:     parentUser,
			Groups:          cred.Groups,
			Action:          iampolicy.CreateUserAdminAction,
			ConditionValues: getConditionValues(r, "", parentUser, claims),
			IsOwner:         owner,
			Claims:          claims,
		}) {
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	if implicitPerm && !GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     accessKey,
		Groups:          cred.Groups,
		Action:          iampolicy.CreateUserAdminAction,
		ConditionValues: getConditionValues(r, "", accessKey, claims),
		IsOwner:         owner,
		Claims:          claims,
		DenyOnly:        true, // check if changing password is explicitly denied.
	}) {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	if r.ContentLength > maxEConfigJSONSize || r.ContentLength == -1 {
		// More than maxConfigSize bytes were available
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAdminConfigTooLarge), r.URL)
		return
	}

	password := cred.SecretKey
	configBytes, err := madmin.DecryptData(password, io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		logger.LogIf(ctx, err)
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAdminConfigBadJSON), r.URL)
		return
	}

	var uinfo madmin.UserInfo
	if err = json.Unmarshal(configBytes, &uinfo); err != nil {
		logger.LogIf(ctx, err)
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAdminConfigBadJSON), r.URL)
		return
	}

	if err = GlobalIAMSys.CreateUser(cred.ParentUser, accessKey, uinfo); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
}

// AddServiceAccount - PUT /minio/admin/v3/add-service-account
func (a adminAPIHandlers) AddServiceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AddServiceAccount")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	password := cred.SecretKey
	reqBytes, err := madmin.DecryptData(password, io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErrWithErr(ErrAdminConfigBadJSON, err), r.URL)
		return
	}

	var createReq madmin.AddServiceAccountReq
	if err = json.Unmarshal(reqBytes, &createReq); err != nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErrWithErr(ErrAdminConfigBadJSON, err), r.URL)
		return
	}

	var (
		targetUser   string
		targetGroups []string
	)

	targetUser = createReq.TargetUser

	// Need permission if we are creating a service acccount
	// for a user <> to the request sender
	if targetUser != "" && targetUser != cred.AccessKey {
		if !GlobalIAMSys.IsAllowed(iampolicy.Args{
			AccountName:     cred.AccessKey,
			Action:          iampolicy.CreateServiceAccountAdminAction,
			ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
			IsOwner:         owner,
			Claims:          claims,
		}) {
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	var ldapUsername string
	if globalLDAPConfig.Enabled && targetUser != "" {
		// If LDAP enabled, service accounts need
		// to be created only for LDAP users.
		var err error
		ldapUsername = targetUser
		targetUser, targetGroups, err = globalLDAPConfig.LookupUserDN(targetUser)
		if err != nil {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
		// targerUser is set to bindDN at this point in time.
		// targetGroups is set to the groups at this point in time.
	} else {
		if cred.IsServiceAccount() || cred.IsTemp() {
			if cred.ParentUser == "" {
				writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx,
					errors.New("service accounts cannot be generated for temporary credentials without parent")), r.URL)
				return
			}
			if targetUser == "" {
				targetUser = cred.ParentUser
			}
		}
		// targetGroups not yet set, so set this to cred.Groups
		if len(targetGroups) == 0 {
			targetGroups = cred.Groups
		}
	}

	var sp *iampolicy.Policy
	if len(createReq.Policy) > 0 {
		sp, err = iampolicy.ParseConfig(bytes.NewReader(createReq.Policy))
		if err != nil {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
	}

	opts := newServiceAccountOpts{
		accessKey:     createReq.AccessKey,
		secretKey:     createReq.SecretKey,
		sessionPolicy: sp,
	}
	if ldapUsername != "" {
		opts.ldapUsername = ldapUsername
	}
	newCred, err := GlobalIAMSys.NewServiceAccount(ctx, targetUser, targetGroups, opts)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	var createResp = madmin.AddServiceAccountResp{
		Credentials: madmin.Credentials{
			AccessKey: newCred.AccessKey,
			SecretKey: newCred.SecretKey,
		},
	}

	data, err := json.Marshal(createResp)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	encryptedData, err := madmin.EncryptData(password, data)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, encryptedData)
}

// UpdateServiceAccount - POST /minio/admin/v3/update-service-account
func (a adminAPIHandlers) UpdateServiceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "UpdateServiceAccount")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))


	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	accessKey := mux.Vars(r)["accessKey"]
	if accessKey == "" {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	svcAccount, _, err := GlobalIAMSys.GetServiceAccount(ctx, accessKey)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	if !GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Action:          iampolicy.UpdateServiceAccountAdminAction,
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
		IsOwner:         owner,
		Claims:          claims,
	}) {
		requestUser := cred.AccessKey
		if cred.ParentUser != "" {
			requestUser = cred.ParentUser
		}

		if requestUser != svcAccount.ParentUser {
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	password := cred.SecretKey
	reqBytes, err := madmin.DecryptData(password, io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErrWithErr(ErrAdminConfigBadJSON, err), r.URL)
		return
	}

	var updateReq madmin.UpdateServiceAccountReq
	if err = json.Unmarshal(reqBytes, &updateReq); err != nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErrWithErr(ErrAdminConfigBadJSON, err), r.URL)
		return
	}

	var sp *iampolicy.Policy
	if len(updateReq.NewPolicy) > 0 {
		sp, err = iampolicy.ParseConfig(bytes.NewReader(updateReq.NewPolicy))
		if err != nil {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
	}
	opts := updateServiceAccountOpts{
		secretKey:     updateReq.NewSecretKey,
		status:        updateReq.NewStatus,
		sessionPolicy: sp,
	}
	err = GlobalIAMSys.UpdateServiceAccount(ctx, cred.ParentUser, accessKey, opts)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessNoContent(w)
}

// InfoServiceAccount - GET /minio/admin/v3/info-service-account
func (a adminAPIHandlers) InfoServiceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "InfoServiceAccount")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	accessKey := mux.Vars(r)["accessKey"]
	if accessKey == "" {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	svcAccount, policy, err := GlobalIAMSys.GetServiceAccount(ctx, accessKey)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	if !GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Action:          iampolicy.ListServiceAccountsAdminAction,
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
		IsOwner:         owner,
		Claims:          claims,
	}) {
		requestUser := cred.AccessKey
		if cred.ParentUser != "" {
			requestUser = cred.ParentUser
		}

		if requestUser != svcAccount.ParentUser {
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	var svcAccountPolicy iampolicy.Policy

	impliedPolicy := policy == nil

	// If policy is empty, check for policy of the parent user
	if !impliedPolicy {
		svcAccountPolicy = svcAccountPolicy.Merge(*policy)
	} else {
		policiesNames, err := GlobalIAMSys.PolicyDBGet(svcAccount.ParentUser, false)
		if err != nil {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
		svcAccountPolicy = svcAccountPolicy.Merge(GlobalIAMSys.GetCombinedPolicy(policiesNames...))
	}

	policyJSON, err := json.MarshalIndent(svcAccountPolicy, "", " ")
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	var infoResp = madmin.InfoServiceAccountResp{
		ParentUser:    svcAccount.ParentUser,
		AccountStatus: svcAccount.Status,
		ImpliedPolicy: impliedPolicy,
		Policy:        string(policyJSON),
	}

	data, err := json.Marshal(infoResp)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	encryptedData, err := madmin.EncryptData(cred.SecretKey, data)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, encryptedData)
}

// ListServiceAccounts - GET /minio/admin/v3/list-service-accounts
func (a adminAPIHandlers) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListServiceAccounts")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))


	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	var targetAccount string

	user := r.URL.Query().Get("user")
	if user != "" {
		if !GlobalIAMSys.IsAllowed(iampolicy.Args{
			AccountName:     cred.AccessKey,
			Action:          iampolicy.ListServiceAccountsAdminAction,
			ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
			IsOwner:         owner,
			Claims:          claims,
		}) {
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
		targetAccount = user
	} else {
		targetAccount = cred.AccessKey
		if cred.ParentUser != "" {
			targetAccount = cred.ParentUser
		}
	}

	serviceAccounts, err := GlobalIAMSys.ListServiceAccounts(ctx, targetAccount)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	var serviceAccountsNames []string

	for _, svc := range serviceAccounts {
		serviceAccountsNames = append(serviceAccountsNames, svc.AccessKey)
	}

	var listResp = madmin.ListServiceAccountsResp{
		Accounts: serviceAccountsNames,
	}

	data, err := json.Marshal(listResp)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	encryptedData, err := madmin.EncryptData(cred.SecretKey, data)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, encryptedData)
}

// DeleteServiceAccount - DELETE /minio/admin/v3/delete-service-account
func (a adminAPIHandlers) DeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteServiceAccount")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, "")
	if s3Err != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	serviceAccount := mux.Vars(r)["accessKey"]
	if serviceAccount == "" {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAdminInvalidArgument), r.URL)
		return
	}

	svcAccount, _, err := GlobalIAMSys.GetServiceAccount(ctx, serviceAccount)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	adminPrivilege := GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Action:          iampolicy.RemoveServiceAccountAdminAction,
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
		IsOwner:         owner,
		Claims:          claims,
	})

	if !adminPrivilege {
		parentUser := cred.AccessKey
		if cred.ParentUser != "" {
			parentUser = cred.ParentUser
		}
		if parentUser != svcAccount.ParentUser {
			// The service account belongs to another user but return not
			// found error to mitigate brute force attacks. or the
			// serviceAccount doesn't exist.
			writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrAdminServiceAccountNotFound), r.URL)
			return
		}
	}

	err = GlobalIAMSys.DeleteServiceAccount(ctx, serviceAccount)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessNoContent(w)
}

// InfoCannedPolicy - GET /minio/admin/v3/info-canned-policy?name={policyName}
func (a adminAPIHandlers) InfoCannedPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "InfoCannedPolicy")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	_ = validateAdminUsersReq(ctx, w, r, iampolicy.GetPolicyAdminAction)

	policy, err := GlobalIAMSys.InfoPolicy(mux.Vars(r)["name"])
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	buf, err := json.MarshalIndent(policy, "", " ")
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
	w.Write(buf)
}

// ListBucketPolicies - GET /minio/admin/v3/list-canned-policies?bucket={bucket}
func (a adminAPIHandlers) ListBucketPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListBucketPolicies")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.ListUserPoliciesAdminAction)

	bucket := mux.Vars(r)["bucket"]
	policies, err := GlobalIAMSys.ListPolicies(cred.ParentUser, bucket)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	var newPolicies = make(map[string]iampolicy.Policy)
	for name, p := range policies {
		_, err = json.Marshal(p)
		if err != nil {
			logger.LogIf(ctx, err)
			continue
		}
		newPolicies[name] = p
	}
	if err = json.NewEncoder(w).Encode(newPolicies); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	w.(http.Flusher).Flush()

}

// ListCannedPolicies - GET /minio/admin/v3/list-canned-policies
func (a adminAPIHandlers) ListCannedPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListCannedPolicies")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.ListUserPoliciesAdminAction)

	policies, err := GlobalIAMSys.ListPolicies(cred.ParentUser, "")
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	var newPolicies = make(map[string]iampolicy.Policy)
	for name, p := range policies {
		_, err = json.Marshal(p)
		if err != nil {
			logger.LogIf(ctx, err)
			continue
		}
		newPolicies[name] = p
	}
	if err = json.NewEncoder(w).Encode(newPolicies); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	w.(http.Flusher).Flush()
}

// RemoveCannedPolicy - DELETE /minio/admin/v3/remove-canned-policy?name=<policy_name>
func (a adminAPIHandlers) RemoveCannedPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "RemoveCannedPolicy")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	_ = validateAdminUsersReq(ctx, w, r, iampolicy.DeletePolicyAdminAction)

	vars := mux.Vars(r)
	policyName := vars["name"]

	if err := GlobalIAMSys.DeletePolicy(policyName); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
}

type AuthResult struct {
	Cred    auth.Credentials
	Owner   bool
	Allowed bool
	Claims  map[string]interface{}
}

func IsAllowed(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "IsAllowed")
	var cred auth.Credentials
	var owner bool
	var s3Err APIErrorCode

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
	}
	var args iampolicy.Args
	json.Unmarshal(body, &args)

	switch getRequestAuthType(r) {
	case authTypeUnknown, authTypeStreamingSigned:
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrSignatureVersionNotSupported), r.URL)
		return
	case authTypePresignedV2, authTypeSignedV2:
		if s3Err = isReqAuthenticatedV2(r); s3Err != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		}
		cred, owner, s3Err = getReqAccessKeyV2(r)
	case authTypeSigned, authTypePresigned:
		region := globalServerRegion
		switch args.Action {
		case policy.GetBucketLocationAction, policy.ListAllMyBucketsAction:
			region = ""
		}
		if s3Err = isReqAuthenticated(ctx, r, region, serviceS3); s3Err != ErrNone {
			return
		}
		cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
	}
	if s3Err != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
	}

	var claims map[string]interface{}
	claims, s3Err = checkClaimsFromToken(r, cred)
	if s3Err != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
	}

	// 验证IAM策略
	allowed := GlobalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Groups:          cred.Groups,
		Action:          args.Action,
		BucketName:      args.BucketName,
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
		ObjectName:      args.ObjectName,
		IsOwner:         owner,
		Claims:          claims,
	})

	ar := AuthResult{
		Cred:    cred,
		Owner:   owner,
		Allowed: allowed,
		Claims:  claims,
	}

	result, _ := json.Marshal(ar)
	writeSuccessResponseJSON(w, result)

}

//func (a adminAPIHandlers) IsAllowed(w http.ResponseWriter, r *http.Request) {
//	ctx := newContext(r, w, "IsAllowed")
//	var cred auth.Credentials
//	var cred auth.Credentials
//	var owner bool
//	var s3Err APIErrorCode
//
//	body, err := ioutil.ReadAll(r.Body)
//	if err != nil {
//		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
//	}
//	var args iampolicy.Args
//	json.Unmarshal(body, &args)
//
//	switch getRequestAuthType(r) {
//	case authTypeUnknown, authTypeStreamingSigned:
//		//return cred, owner, ErrSignatureVersionNotSupported
//		return
//	case authTypePresignedV2, authTypeSignedV2:
//		if s3Err = isReqAuthenticatedV2(r); s3Err != ErrNone {
//			return
//		}
//		cred, owner, s3Err = getReqAccessKeyV2(r)
//	case authTypeSigned, authTypePresigned:
//		region := globalServerRegion
//		switch args.Action {
//		case policy.GetBucketLocationAction, policy.ListAllMyBucketsAction:
//			region = ""
//		}
//		if s3Err = isReqAuthenticated(ctx, r, region, serviceS3); s3Err != ErrNone {
//			return
//		}
//		cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
//	}
//	if s3Err != ErrNone {
//		return
//	}
//
//	var claims map[string]interface{}
//	claims, s3Err = checkClaimsFromToken(r, cred)
//	if s3Err != ErrNone {
//		return
//	}
//
//	// 验证IAM策略
//	allowed := GlobalIAMSys.IsAllowed(iampolicy.Args{
//		AccountName:     cred.AccessKey,
//		Groups:          cred.Groups,
//		Action:          args.Action,
//		BucketName:      args.BucketName,
//		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
//		ObjectName:      args.ObjectName,
//		IsOwner:         owner,
//		Claims:          claims,
//	})
//
//	//allowed := GlobalIAMSys.IsAllowed(args)
//	s := make(map[string]interface{})
//	s["Allowed"] = allowed
//	//s["allowed"] = "false"
//	//if allowed {
//	//	s["allowed"] = "true"
//	//}
//	result, _ := json.Marshal(s)
//	writeSuccessResponseJSON(w, result)
//
//}

// AddCannedPolicy - PUT /minio/admin/v3/add-canned-policy?name=<policy_name>
func (a adminAPIHandlers) AddCannedPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AddCannedPolicy")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	cred := validateAdminUsersReq(ctx, w, r, iampolicy.CreatePolicyAdminAction)

	vars := mux.Vars(r)
	policyName := vars["name"]

	// Error out if Content-Length is missing.
	if r.ContentLength <= 0 {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	// Error out if Content-Length is beyond allowed size.
	if r.ContentLength > maxBucketPolicySize {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL)
		return
	}

	iamPolicy, err := iampolicy.ParseConfig(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	// Version in policy must not be empty
	if iamPolicy.Version == "" {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrMalformedPolicy), r.URL)
		return
	}

	if err = GlobalIAMSys.SetPolicy(cred.ParentUser, policyName, *iamPolicy); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
}

// SetPolicyForUserOrGroup - PUT /minio/admin/v3/set-policy?policy=xxx&user-or-group=?[&is-group]
func (a adminAPIHandlers) SetPolicyForUserOrGroup(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "SetPolicyForUserOrGroup")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	_ = validateAdminUsersReq(ctx, w, r, iampolicy.AttachPolicyAdminAction)

	vars := mux.Vars(r)
	policyName := vars["policyName"]
	entityName := vars["userOrGroup"]
	isGroup := vars["isGroup"] == "true"

	if !isGroup {
		ok, _, err := GlobalIAMSys.IsTempUser(entityName)
		if err != nil && err != errNoSuchUser {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
		if ok {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, errIAMActionNotAllowed), r.URL)
			return
		}
	}

	// only support admin or tenant users
	if err := GlobalIAMSys.PolicyDBSet(entityName, policyName, isGroup); err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
}
