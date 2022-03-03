

package internal

import (
	iampolicy "github.com/minio/pkg/iam/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"mt-iam/internal/handlers"
	xhttp "mt-iam/internal/http"
	"mt-iam/logger"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	httpRequestsDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3_ttfb_seconds",
			Help:    "Time taken by requests served by current MinIO server instance",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"api"},
	)
	minioVersionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "minio",
			Name:      "version_info",
			Help:      "Version of current MinIO server instance",
		},
		[]string{
			// current version
			"version",
			// commit-id of the current version
			"commit",
		},
	)
)

const (
	healMetricsNamespace = "self_heal"
	gatewayNamespace     = "gateway"
	cacheNamespace       = "cache"
	s3Namespace          = "s3"
	bucketNamespace      = "bucket"
	minioNamespace       = "minio"
	diskNamespace        = "disk"
	interNodeNamespace   = "internode"
)

func init() {
	prometheus.MustRegister(httpRequestsDuration)
	prometheus.MustRegister(newMinioCollector())
	prometheus.MustRegister(minioVersionInfo)
}

// newMinioCollector describes the collector
// and returns reference of minioCollector
// It creates the Prometheus Description which is used
// to define metric and  help string
func newMinioCollector() *minioCollector {
	return &minioCollector{
		desc: prometheus.NewDesc("minio_stats", "Statistics exposed by MinIO server", nil, nil),
	}
}

// minioCollector is the Custom Collector
type minioCollector struct {
	desc *prometheus.Desc
}

// Describe sends the super-set of all possible descriptors of metrics
func (c *minioCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Version - version time.RFC3339.
var (
	Version = "DEVELOPMENT.GOGET"

	// CommitID - latest commit id.
	CommitID = "DEVELOPMENT.GOGET"
)

// Collect is called by the Prometheus registry when collecting metrics.
func (c *minioCollector) Collect(ch chan<- prometheus.Metric) {

	// Expose MinIO's version information
	minioVersionInfo.WithLabelValues(Version, CommitID).Set(1.0)

	storageMetricsPrometheus(ch)
	nodeHealthMetricsPrometheus(ch)
	bucketUsageMetricsPrometheus(ch)
	networkMetricsPrometheus(ch)
	httpMetricsPrometheus(ch)
	cacheMetricsPrometheus(ch)
	gatewayMetricsPrometheus(ch)
	healingMetricsPrometheus(ch)
}

func nodeHealthMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// collects healing specific metrics for MinIO instance in Prometheus specific format
// and sends to given channel
func healingMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// collects gateway specific metrics for MinIO instance in Prometheus specific format
// and sends to given channel
func gatewayMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// collects cache metrics for MinIO server in Prometheus specific format
// and sends to given channel
func cacheMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// collects http metrics for MinIO server in Prometheus specific format
// and sends to given channel
func httpMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// collects network metrics for MinIO server in Prometheus specific format
// and sends to given channel
func networkMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// Populates prometheus with bucket usage metrics, this metrics
// is only enabled if scanner is enabled.
func bucketUsageMetricsPrometheus(ch chan<- prometheus.Metric) {

}

// collects storage metrics for MinIO server in Prometheus specific format
// and sends to given channel
func storageMetricsPrometheus(ch chan<- prometheus.Metric) {

}

func metricsHandler() http.Handler {

	registry := prometheus.NewRegistry()

	err := registry.Register(minioVersionInfo)
	logger.LogIf(GlobalContext, err)

	err = registry.Register(httpRequestsDuration)
	logger.LogIf(GlobalContext, err)

	err = registry.Register(newMinioCollector())
	logger.LogIf(GlobalContext, err)

	gatherers := prometheus.Gatherers{
		prometheus.DefaultGatherer,
		registry,
	}
	// Delegate http serving to Prometheus client library, which will call collector.Collect.
	return promhttp.InstrumentMetricHandler(
		registry,
		promhttp.HandlerFor(gatherers,
			promhttp.HandlerOpts{
				ErrorHandling: promhttp.ContinueOnError,
			}),
	)

}

// AuthMiddleware checks if the bearer token is valid and authorized.
func AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, owner, authErr := webRequestAuthenticate(r)
		if authErr != nil || !claims.VerifyIssuer("prometheus", true) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// For authenticated users apply IAM policy.
		if !GlobalIAMSys.IsAllowed(iampolicy.Args{
			AccountName:     claims.AccessKey,
			Action:          iampolicy.PrometheusAdminAction,
			ConditionValues: getConditionValues(r, "", claims.AccessKey, claims.Map()),
			IsOwner:         owner,
			Claims:          claims.Map(),
		}) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func getConditionValues(r *http.Request, lc string, username string, claims map[string]interface{}) map[string][]string {
	currTime := UTCNow()

	principalType := "Anonymous"
	if username != "" {
		principalType = "User"
		if len(claims) > 0 {
			principalType = "AssumedRole"
		}
		//if username == globalActiveCred.AccessKey {
		//	principalType = "Account"
		//}
	}

	vid := r.URL.Query().Get("versionId")
	if vid == "" {
		if u, err := url.Parse(r.Header.Get(xhttp.AmzCopySource)); err == nil {
			vid = u.Query().Get("versionId")
		}
	}

	authType := getRequestAuthType(r)
	var signatureVersion string
	switch authType {
	case authTypeSignedV2, authTypePresignedV2:
		signatureVersion = signV2Algorithm
	case authTypeSigned, authTypePresigned, authTypeStreamingSigned, authTypePostPolicy:
		signatureVersion = signV4Algorithm
	}

	var authtype string
	switch authType {
	case authTypePresignedV2, authTypePresigned:
		authtype = "REST-QUERY-STRING"
	case authTypeSignedV2, authTypeSigned, authTypeStreamingSigned:
		authtype = "REST-HEADER"
	case authTypePostPolicy:
		authtype = "POST"
	}

	args := map[string][]string{
		"CurrentTime":      {currTime.Format(time.RFC3339)},
		"EpochTime":        {strconv.FormatInt(currTime.Unix(), 10)},
		"SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"SourceIp":         {handlers.GetSourceIP(r)},
		"UserAgent":        {r.UserAgent()},
		"Referer":          {r.Referer()},
		"principaltype":    {principalType},
		"userid":           {username},
		"username":         {username},
		"versionid":        {vid},
		"signatureversion": {signatureVersion},
		"authType":         {authtype},
	}

	if lc != "" {
		args["LocationConstraint"] = []string{lc}
	}

	cloneHeader := r.Header.Clone()

	for _, objLock := range []string{
		xhttp.AmzObjectLockMode,
		xhttp.AmzObjectLockLegalHold,
		xhttp.AmzObjectLockRetainUntilDate,
	} {
		if values, ok := cloneHeader[objLock]; ok {
			args[strings.TrimPrefix(objLock, "X-Amz-")] = values
		}
		cloneHeader.Del(objLock)
	}

	for key, values := range cloneHeader {
		if existingValues, found := args[key]; found {
			args[key] = append(existingValues, values...)
		} else {
			args[key] = values
		}
	}

	var cloneURLValues = url.Values{}
	for k, v := range r.URL.Query() {
		cloneURLValues[k] = v
	}

	for _, objLock := range []string{
		xhttp.AmzObjectLockMode,
		xhttp.AmzObjectLockLegalHold,
		xhttp.AmzObjectLockRetainUntilDate,
	} {
		if values, ok := cloneURLValues[objLock]; ok {
			args[strings.TrimPrefix(objLock, "X-Amz-")] = values
		}
		cloneURLValues.Del(objLock)
	}

	for key, values := range cloneURLValues {
		if existingValues, found := args[key]; found {
			args[key] = append(existingValues, values...)
		} else {
			args[key] = values
		}
	}

	// JWT specific values
	for k, v := range claims {
		vStr, ok := v.(string)
		if ok {
			// Special case for AD/LDAP STS users
			if k == ldapUser {
				args["user"] = []string{vStr}
			} else if k == ldapUserN {
				args["username"] = []string{vStr}
			} else {
				args[k] = []string{vStr}
			}
		}
	}

	return args
}
