package internal

import (
	"github.com/dustin/go-humanize"
	xldap "mt-iam/conf/ldap"
	"mt-iam/conf/openid"
	"mt-iam/conf/policy/opa"
	"mt-iam/internal/auth"
	"mt-iam/internal/pubsub"
	"sync"
	"time"
)

var (
	// OPA policy system.
	globalPolicyOPA    *opa.Opa
	globalOpenIDConfig openid.Config
	globalActiveCred   auth.Credentials
	GlobalIAMSys       *IAMSys
	globalLDAPConfig   xldap.Config
	// Authorization validators list.
	globalOpenIDValidators *openid.Validators
	globalIsDistErasure    = false
	// This flag is set to 'us-east-1' by default
	globalServerRegion = globalMinioDefaultRegion
	globalDomainNames  []string
	// Deployment ID - unique per deployment
	globalDeploymentID string
	// The maximum allowed time difference between the incoming request
	// date and server date during signature verification.
	globalMaxSkewTime   = 150000 * time.Minute // 15 minutes skew allowed.
	globalTrace         = pubsub.New()
	globalLocalNodeName string
	globalHTTPStats     = newHTTPStats()
	globalFlushLogging  = make(chan struct{}, 1)
	GloablLoggingConfig sync.Map
	globalAPIConfig     = apiConfig{listQuorum: 30}
	//notify cronjob push file to ipfs
	GlobalNotifyCronJob = make(chan string, 1000)
)

const (
	maxLocationConstraintSize = 3 * humanize.MiByte
	globalWindowsOSName       = "windows"
	// Refresh interval to update in-memory iam config cache.
	globalRefreshIAMInterval = 5 * time.Minute
	globalDirSuffix          = "__XLDIR__"
	globalMinioDefaultRegion = ""
	// Limit fields size (except file) to 1Mib since Policy document
	// can reach that size according to https://aws.amazon.com/articles/1434
	maxFormFieldSize = int64(1 * humanize.MiByte)
)

func Start() {
	GlobalIAMSys = NewIAMSys()
}
