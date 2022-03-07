

package internal

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/klauspost/compress/gzhttp"
	"github.com/klauspost/compress/gzip"
	"github.com/minio/madmin-go"
)

const (
	adminPathPrefix       = minioReservedBucketPath + "/admin"
	adminAPIVersion       = madmin.AdminAPIVersion
	adminAPIVersionPrefix = SlashSeparator + adminAPIVersion
)

// adminAPIHandlers provides HTTP handlers for MinIO admin API.
type adminAPIHandlers struct{}

// RegisterAdminRouter - Add handler functions for each service REST API routes.
func RegisterAdminRouter(router *mux.Router) {

	adminAPI := adminAPIHandlers{}
	// Admin router
	adminRouter := router.PathPrefix(adminPathPrefix).Subrouter()

	/// Service operations

	adminVersions := []string{
		adminAPIVersionPrefix,
	}

	gz := func(h http.HandlerFunc) http.HandlerFunc {
		return h
	}

	wrapper, err := gzhttp.NewWrapper(gzhttp.MinSize(1000), gzhttp.CompressionLevel(gzip.BestSpeed))
	if err == nil {
		gz = func(h http.HandlerFunc) http.HandlerFunc {
			return wrapper(h)
		}
	}
	for _, adminVersion := range adminVersions {
		// -- IAM APIs --
		//adminRouter.Methods(http.MethodPost).Path(adminVersion + "/is-allowed").HandlerFunc(adminAPI.IsAllowed)
		// Add policy IAM
		adminRouter.Methods(http.MethodPut).Path(adminVersion+"/add-canned-policy").HandlerFunc(gz(httpTraceAll(adminAPI.AddCannedPolicy))).Queries("name", "{name:.*}")

		//// Add user IAM
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/accountinfo").HandlerFunc(gz(httpTraceAll(adminAPI.AccountInfoHandler)))

		adminRouter.Methods(http.MethodPut).Path(adminVersion+"/add-user").HandlerFunc(gz(httpTraceHdrs(adminAPI.AddUser))).Queries("accessKey", "{accessKey:.*}")

		adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-user-status").HandlerFunc(gz(httpTraceHdrs(adminAPI.SetUserStatus))).Queries("accessKey", "{accessKey:.*}").Queries("status", "{status:.*}")

		// Service accounts ops
		adminRouter.Methods(http.MethodPut).Path(adminVersion + "/add-service-account").HandlerFunc(gz(httpTraceHdrs(adminAPI.AddServiceAccount)))
		adminRouter.Methods(http.MethodPost).Path(adminVersion+"/update-service-account").HandlerFunc(gz(httpTraceHdrs(adminAPI.UpdateServiceAccount))).Queries("accessKey", "{accessKey:.*}")
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/info-service-account").HandlerFunc(gz(httpTraceHdrs(adminAPI.InfoServiceAccount))).Queries("accessKey", "{accessKey:.*}")
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-service-accounts").HandlerFunc(gz(httpTraceHdrs(adminAPI.ListServiceAccounts)))
		adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/delete-service-account").HandlerFunc(gz(httpTraceHdrs(adminAPI.DeleteServiceAccount))).Queries("accessKey", "{accessKey:.*}")

		// Info policy IAM latest
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/info-canned-policy").HandlerFunc(gz(httpTraceHdrs(adminAPI.InfoCannedPolicy))).Queries("name", "{name:.*}")
		// List policies latest
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/list-canned-policies").HandlerFunc(gz(httpTraceHdrs(adminAPI.ListBucketPolicies))).Queries("bucket", "{bucket:.*}")
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-canned-policies").HandlerFunc(gz(httpTraceHdrs(adminAPI.ListCannedPolicies)))

		// Remove policy IAM
		adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/remove-canned-policy").HandlerFunc(gz(httpTraceHdrs(adminAPI.RemoveCannedPolicy))).Queries("name", "{name:.*}")

		// Set user or group policy
		adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-user-or-group-policy").
			HandlerFunc(gz(httpTraceHdrs(adminAPI.SetPolicyForUserOrGroup))).
			Queries("policyName", "{policyName:.*}", "userOrGroup", "{userOrGroup:.*}", "isGroup", "{isGroup:true|false}")

		// Remove user IAM
		adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/remove-user").HandlerFunc(gz(httpTraceHdrs(adminAPI.RemoveUser))).Queries("accessKey", "{accessKey:.*}")

		// List users
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/list-users").HandlerFunc(gz(httpTraceHdrs(adminAPI.ListBucketUsers))).Queries("bucket", "{bucket:.*}")
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-users").HandlerFunc(gz(httpTraceHdrs(adminAPI.ListUsers)))

		// User info
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/user-info").HandlerFunc(gz(httpTraceHdrs(adminAPI.GetUserInfo))).Queries("accessKey", "{accessKey:.*}")
		// Add/Remove members from group
		adminRouter.Methods(http.MethodPut).Path(adminVersion + "/update-group-members").HandlerFunc(gz(httpTraceHdrs(adminAPI.UpdateGroupMembers)))

		// Get Group
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/group").HandlerFunc(gz(httpTraceHdrs(adminAPI.GetGroup))).Queries("group", "{group:.*}")

		// List Groups
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/groups").HandlerFunc(gz(httpTraceHdrs(adminAPI.ListGroups)))

		// Set Group Status
		adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-group-status").HandlerFunc(gz(httpTraceHdrs(adminAPI.SetGroupStatus))).Queries("group", "{group:.*}").Queries("status", "{status:.*}")

	}
}
