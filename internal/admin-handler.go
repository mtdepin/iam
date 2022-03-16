package internal

import (
	"encoding/json"
	"github.com/minio/madmin-go"
	"mt-iam/pkg/logger"
	"net/http"
)

// ServerInfoHandler - GET /minio/admin/v3/info
// ----------
// Get server information
func (a adminAPIHandlers) ServerInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ServerInfo")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	// Validate request signature.
	//_, adminAPIErr := checkAdminRequestAuth(ctx, r, iampolicy.ServerInfoAdminAction, "")
	//if adminAPIErr != ErrNone {
	//	writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(adminAPIErr), r.URL)
	//	return
	//}

	// Marshal API response
	info :=  madmin.InfoMessage{
		Mode:         "",
		Domain:       []string {"localhost"},
		Region:       "",
		SQSARN:        []string {"SQSARN"},
		DeploymentID: "",
		Buckets:      madmin.Buckets{},
		Objects:      madmin.Objects{},
		Usage:        madmin.Usage{},
		Services:     madmin.Services{},
		Backend:      nil,
		Servers:      []madmin.ServerProperties{
			{
				State:      "",
				Endpoint:   "",
				Uptime:     0,
				Version:    "",
				CommitID:   "",
				Network:    nil,
				Disks:      nil,
				PoolNumber: 0,
				MemStats:   madmin.MemStats{},
			},
		},
	}
	jsonBytes, err := json.Marshal(info)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	// Reply with storage information (across nodes in a
	// distributed setup) as json.
	writeSuccessResponseJSON(w, jsonBytes)
}

