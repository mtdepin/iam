

package audit

import (
	"net/http"
	"time"

	"mt-iam/internal/handlers"
)

// Version - represents the current version of audit log structure.
const Version = "1"

// Entry - audit entry logs.
/*
type Entry struct {
	Version      string `json:"version"`
	DeploymentID string `json:"deploymentid,omitempty"`
	Time         string `json:"time"`
	Trigger      string `json:"trigger"`
	API          struct {
		Name            string `json:"name,omitempty"`
		Bucket          string `json:"bucket,omitempty"`
		Object          string `json:"object,omitempty"`
		Status          string `json:"status,omitempty"`
		StatusCode      int    `json:"statusCode,omitempty"`
		TimeToFirstByte string `json:"timeToFirstByte,omitempty"`
		TimeToResponse  string `json:"timeToResponse,omitempty"`
	} `json:"api"`
	RemoteHost string                 `json:"remotehost,omitempty"`
	RequestID  string                 `json:"requestID,omitempty"`
	UserAgent  string                 `json:"userAgent,omitempty"`
	ReqClaims  map[string]interface{} `json:"requestClaims,omitempty"`
	ReqQuery   map[string]string      `json:"requestQuery,omitempty"`
	ReqHeader  map[string]string      `json:"requestHeader,omitempty"`
	RespHeader map[string]string      `json:"responseHeader,omitempty"`
	Tags       map[string]interface{} `json:"tags,omitempty"`
}
*/
type Entry struct {
	Timestamp          time.Time `json:"@timestamp"`
	RemoteIP           string    `json:"remoteIP"`           // 请求者的IP地址
	Reserved1          string    `json:"-"`                  // 保留字段，固定值为-
	Reserved2          string    `json:"-"`                  // 保留字段，固定值为-
	Time               string    `json:"time"`               // 收到请求的时间
	RequestURL         string    `json:"requestURL"`         // 请求的URL
	HTTPStatus         int       `json:"httpStatus"`         // 返回的HTTP状态码
	SentBytes          string    `json:"sentBytes"`          // 请求产生的下行流量
	RequestTime        string    `json:"requestTime"`        // 请求耗费的时间，单位：ms
	Referer            string    `json:"referer"`            // 请求的HTTP Referer
	UserAgent          string    `json:"userAgent"`          // HTTP的User-Agent头
	HostName           string    `json:"hostName"`           // 请求访问的目标域名
	RequestID          string    `json:"requestID"`          // 请求的Request ID
	LoggingFlag        bool      `json:"loggingFlag"`        // 是否已开启日志转存
	RequesterID        string    `json:"requesterID"`        // 请求者的用户ID，取值-表示匿名访问
	Operation          string    `json:"operation"`          // 请求类型
	BucketName         string    `json:"bucketName"`         // 请求的目标Bucket名称
	ObjectName         string    `json:"objectName"`         // 请求的目标Object名称
	ObjectSize         string    `json:"objectSize"`         // 目标Object大小
	ServerCostTime     string    `json:"serverCostTime"`     // 本次请求所花的时间，单位：毫秒
	ErrorCode          string    `json:"errorCode"`          // 返回的错误码，取值-表示未返回错误码
	RequestLength      int64     `json:"requestLength"`      // 请求的长度
	UserID             string    `json:"userID"`             // Bucket拥有者ID
	DeltaDataSize      string    `json:"deltaDataSize"`      // Object大小的变化量，取值-表示此次请求不涉及Object的写入操作
	SyncRequest        string    `json:"syncRequest"`        // 请求是否为CDN回源请求
	StorageClass       string    `json:"storageClass"`       // 目标Object的存储类型
	TargetStorageClass string    `json:"targetStorageClass"` // 是否通过生命周期规则或CopyObject转换了Object的存储类型
	AccessPoint        string    `json:"accessPoint"`        // 通过传输加速域名访问目标Bucket时使用的传输加速接入点
	AccessKeyID        string    `json:"accessKeyID"`        // 请求者的AccessKey ID，取值-表示匿名请求
	Version            string    `json:"version"`
	DeploymentID       string    `json:"deploymentID"`
}

// NewEntry - constructs an audit entry object with some fields filled
func NewEntry(deploymentID string) Entry {
	return Entry{
		Version:      Version,
		DeploymentID: deploymentID,
		// Time:         time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// ToEntry - constructs an audit entry from a http request
/*
func ToEntry(w http.ResponseWriter, r *http.Request, reqClaims map[string]interface{}, deploymentID string) Entry {

	entry := NewEntry(deploymentID)

	entry.RemoteHost = handlers.GetSourceIP(r)
	entry.UserAgent = r.UserAgent()
	entry.ReqClaims = reqClaims

	q := r.URL.Query()
	reqQuery := make(map[string]string, len(q))
	for k, v := range q {
		reqQuery[k] = strings.Join(v, ",")
	}
	entry.ReqQuery = reqQuery

	reqHeader := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		reqHeader[k] = strings.Join(v, ",")
	}
	entry.ReqHeader = reqHeader

	wh := w.Header()
	entry.RequestID = wh.Get(xhttp.AmzRequestID)
	respHeader := make(map[string]string, len(wh))
	for k, v := range wh {
		respHeader[k] = strings.Join(v, ",")
	}
	entry.RespHeader = respHeader

	if etag := respHeader[xhttp.ETag]; etag != "" {
		respHeader[xhttp.ETag] = strings.Trim(etag, `"`)
	}

	return entry
}

*/

func ToEntry(w http.ResponseWriter, r *http.Request, reqClaims map[string]interface{}, deploymentID string) Entry {
	entry := NewEntry(deploymentID)
	entry.RemoteIP = handlers.GetSourceIP(r)
	return entry
}
