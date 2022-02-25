package internal

import (
	"context"
	"fmt"
	xhttp "mt-iam/internal/http"
	"net/http"
	"net/url"
	"strconv"
)

const (
	// Means no response type.
	mimeNone mimeType = ""
	// Means response type is JSON.
	mimeJSON mimeType = "application/json"
	// Means response type is XML.
	mimeXML mimeType = "application/xml"
)

// mimeType represents various MIME type used API responses.
type mimeType string

// writeSuccessResponseXML writes success headers and response if any,
// with content-type set to `application/xml`.
func writeSuccessResponseXML(w http.ResponseWriter, response []byte) {
	writeResponse(w, http.StatusOK, response, mimeXML)
}

// writeErrorResponseJSON - writes error response in JSON format;
// useful for admin APIs.
func writeErrorResponseJSON(ctx context.Context, w http.ResponseWriter, err APIError, reqURL *url.URL) {
	// Generate error response.
	errorResponse := getAPIErrorResponse(ctx, err, reqURL.Path, w.Header().Get(xhttp.AmzRequestID), globalDeploymentID)
	encodedErrorResponse := encodeResponseJSON(errorResponse)
	writeResponse(w, err.HTTPStatusCode, encodedErrorResponse, mimeJSON)
}

// writeSuccessNoContent writes success headers with http status 204
func writeSuccessNoContent(w http.ResponseWriter) {
	writeResponse(w, http.StatusNoContent, nil, mimeNone)
}
func writeResponse(w http.ResponseWriter, statusCode int, response []byte, mType mimeType) {
	setCommonHeaders(w)
	if mType != mimeNone {
		w.Header().Set(xhttp.ContentType, string(mType))
	}
	w.Header().Set(xhttp.ContentLength, strconv.Itoa(len(response)))
	w.WriteHeader(statusCode)
	if response != nil {
		w.Write(response)
		w.(http.Flusher).Flush()
	}
}

// writeErrorRespone writes error headers
func writeErrorResponse(ctx context.Context, w http.ResponseWriter, err APIError, reqURL *url.URL) {
	switch err.Code {
	case "SlowDown", "XMinioServerNotInitialized", "XMinioReadQuorum", "XMinioWriteQuorum":
		// Set retry-after header to indicate user-agents to retry request after 120secs.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
		w.Header().Set(xhttp.RetryAfter, "120")
	case "InvalidRegion":
		err.Description = fmt.Sprintf("Region does not match; expecting '%s'.", globalServerRegion)
	case "AuthorizationHeaderMalformed":
		err.Description = fmt.Sprintf("The authorization header is malformed; the region is wrong; expecting '%s'.", globalServerRegion)
	}

	// Generate error response.
	errorResponse := getAPIErrorResponse(ctx, err, reqURL.Path,
		w.Header().Get(xhttp.AmzRequestID), globalDeploymentID)
	encodedErrorResponse := encodeResponse(errorResponse)
	writeResponse(w, err.HTTPStatusCode, encodedErrorResponse, mimeXML)
}

func writeErrorResponseString(ctx context.Context, w http.ResponseWriter, err APIError, reqURL *url.URL) {
	// Generate string error response.
	writeResponse(w, err.HTTPStatusCode, []byte(err.Description), mimeNone)
}

// writeSuccessResponseJSON writes success headers and response if any,
// with content-type set to `application/json`.
func writeSuccessResponseJSON(w http.ResponseWriter, response []byte) {
	writeResponse(w, http.StatusOK, response, mimeJSON)
}
