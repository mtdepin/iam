package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"mt-iam/internal/handlers"
	xhttp "mt-iam/internal/http"
	"mt-iam/pkg/logger"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	SlashSeparator        = "/"
	slashSeparator        = "/"
	dynamicTimeoutLogSize = 16
	DEFAULT_USER_QUOTA    = 20
)

// Returns the mode in which MinIO is running
func IamPolicyClaimNameSA() string {
	return "sa-policy"
}
func IamPolicyClaimNameOpenID() string {
	return globalOpenIDConfig.ClaimPrefix + globalOpenIDConfig.ClaimName
}

// pathJoin - like path.Join() but retains trailing SlashSeparator of the last element
func pathJoin(elem ...string) string {
	trailingSlash := ""
	if len(elem) > 0 {
		if HasSuffix(elem[len(elem)-1], SlashSeparator) {
			trailingSlash = SlashSeparator
		}
	}
	return path.Join(elem...) + trailingSlash
}
func iamPolicyClaimNameSA() string {
	return "sa-policy"
}

// HasSuffix - Suffix matcher string matches suffix in a platform specific way.
// For example on windows since its case insensitive we are supposed
// to do case insensitive checks.
func HasSuffix(s string, suffix string) bool {
	if runtime.GOOS == globalWindowsOSName {
		return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
	}
	return strings.HasSuffix(s, suffix)
}

// timeouts that are dynamically adapted based on actual usage results
type dynamicTimeout struct {
	timeout int64
	minimum int64
	entries int64
	log     [dynamicTimeoutLogSize]time.Duration
	mutex   sync.Mutex
}

// newDynamicTimeout returns a new dynamic timeout initialized with timeout value
func newDynamicTimeout(timeout, minimum time.Duration) *dynamicTimeout {
	if timeout <= 0 || minimum <= 0 {
		panic("newDynamicTimeout: negative or zero timeout")
	}
	if minimum > timeout {
		minimum = timeout
	}
	return &dynamicTimeout{timeout: int64(timeout), minimum: int64(minimum)}
}

// Reverse process of encodeDirObject()
func decodeDirObject(object string) string {
	if HasSuffix(object, globalDirSuffix) {
		return strings.TrimSuffix(object, globalDirSuffix) + slashSeparator
	}
	return object
}

func iamPolicyClaimNameOpenID() string {
	return globalOpenIDConfig.ClaimPrefix + globalOpenIDConfig.ClaimName
}

// UTCNow - returns current UTC time.
func UTCNow() time.Time {
	return time.Now().UTC()
}

// similar to unescapeGeneric but never returns any error if the unescaping
// fails, returns the input as is in such occasion, not meant to be
// used where strict validation is expected.
func likelyUnescapeGeneric(p string, escapeFn func(string) (string, error)) string {
	ep, err := unescapeGeneric(p, escapeFn)
	if err != nil {
		return p
	}
	return ep
}

// unescapeGeneric is similar to url.PathUnescape or url.QueryUnescape
// depending on input, additionally also handles situations such as
// `//` are normalized as `/`, also removes any `/` prefix before
// returning.
func unescapeGeneric(p string, escapeFn func(string) (string, error)) (string, error) {
	ep, err := escapeFn(p)
	if err != nil {
		return "", err
	}
	return trimLeadingSlash(ep), nil
}

func trimLeadingSlash(ep string) string {
	if len(ep) > 0 && ep[0] == '/' {
		// Path ends with '/' preserve it
		if ep[len(ep)-1] == '/' && len(ep) > 1 {
			ep = path.Clean(ep)
			ep += slashSeparator
		} else {
			ep = path.Clean(ep)
		}
		ep = ep[1:]
	}
	return ep
}

// Returns context with ReqInfo details set in the context.
func newContext(r *http.Request, w http.ResponseWriter, api string) context.Context {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object := likelyUnescapeGeneric(vars["object"], url.PathUnescape)
	prefix := likelyUnescapeGeneric(vars["prefix"], url.QueryUnescape)
	if prefix != "" {
		object = prefix
	}
	uid, _ := JudgeUserID(r.Context())
	reqInfo := &logger.ReqInfo{
		Uid:          uid,
		DeploymentID: globalDeploymentID,
		RequestID:    w.Header().Get(xhttp.AmzRequestID),
		RemoteHost:   handlers.GetSourceIP(r),
		Host:         getHostName(r),
		UserAgent:    r.UserAgent(),
		API:          api,
		BucketName:   bucket,
		ObjectName:   object,
	}
	return logger.SetReqInfo(r.Context(), reqInfo)
}

func contains(slice interface{}, elem interface{}) bool {
	v := reflect.ValueOf(slice)
	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Interface() == elem {
				return true
			}
		}
	}
	return false
}

// xmlDecoder provide decoded value in xml.
func xmlDecoder(body io.Reader, v interface{}, size int64) error {
	var lbody io.Reader
	if size > 0 {
		lbody = io.LimitReader(body, size)
	} else {
		lbody = body
	}
	d := xml.NewDecoder(lbody)
	// Ignore any encoding set in the XML body
	d.CharsetReader = nopCharsetConverter
	return d.Decode(v)
}

// nopCharsetConverter is a dummy charset convert which just copies input to output,
// it is used to ignore custom encoding charset in S3 XML body.
func nopCharsetConverter(label string, input io.Reader) (io.Reader, error) {
	return input, nil
}

const Ctx_TenantId = "TenantId"

// dump the request into a string in JSON format.
func dumpRequest(r *http.Request) string {
	header := r.Header.Clone()
	header.Set("Host", r.Host)
	// Replace all '%' to '%%' so that printer format parser
	// to ignore URL encoded values.
	rawURI := strings.Replace(r.RequestURI, "%", "%%", -1)
	req := struct {
		Method     string      `json:"method"`
		RequestURI string      `json:"reqURI"`
		Header     http.Header `json:"header"`
	}{r.Method, rawURI, header}

	var buffer bytes.Buffer
	enc := json.NewEncoder(&buffer)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&req); err != nil {
		// Upon error just return Go-syntax representation of the value
		return fmt.Sprintf("%#v", req)
	}

	// Formatted string.
	return strings.TrimSpace(buffer.String())
}

func JudgeUserID(ctx context.Context) (int, bool) {
	c := ctx.Value(Ctx_TenantId)
	value := reflect.ValueOf(c)
	if value.IsValid() {
		if value.IsZero() {
			return 0, false
		}

		na, ok := c.(int)
		if ok {
			return na, ok
		} else {
			if na, ok := c.(float64); ok {
				return int(na), ok
			}
		}
	}
	return 0, false
}
