package internal

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"mt-iam/internal/crypto"
	xhttp "mt-iam/internal/http"
	"net/http"
)

// Encodes the response headers into XML format.
func encodeResponse(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	e := xml.NewEncoder(&bytesBuffer)
	e.Encode(response)
	return bytesBuffer.Bytes()
}

// Encodes the response headers into JSON format.
func encodeResponseJSON(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	e := json.NewEncoder(&bytesBuffer)
	e.Encode(response)
	return bytesBuffer.Bytes()
}

// Write http common headers
func setCommonHeaders(w http.ResponseWriter) {
	// Set the "Server" http header.
	w.Header().Set(xhttp.ServerInfo, "MaitianOSS")

	// Set `x-amz-bucket-region` only if region is set on the server
	// by default minio uses an empty region.
	if region := globalServerRegion; region != "" {
		w.Header().Set(xhttp.AmzBucketRegion, region)
	}
	w.Header().Set(xhttp.AcceptRanges, "bytes")

	// Remove sensitive information
	crypto.RemoveSensitiveHeaders(w.Header())
}
