package internal

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"mt-iam/internal/auth"
	"mt-iam/internal/crypto"
	"mt-iam/internal/event"
	"mt-iam/internal/hash"
	"mt-iam/pkg/logger"
	"net/http"

	"strings"
)

const (
	maxEConfigJSONSize = 262272
)

var (
	errInvalidEncryptionParameters = errors.New("The encryption parameters are not applicable to this object")

	errInvalidSSEParameters = errors.New("The SSE-C key for key-rotation is not correct") // special access denied
	errKMSNotConfigured     = errors.New("KMS not configured for a server side encrypted object")
)

// AdminError - is a generic error for all admin APIs.
type AdminError struct {
	Code       string
	Message    string
	StatusCode int
}

func (ae AdminError) Error() string {
	return ae.Message
}

// APIError structure
type APIError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

// APIErrorResponse - error response format
type APIErrorResponse struct {
	XMLName    xml.Name `xml:"Error" json:"-"`
	Code       string
	Message    string
	Key        string `xml:"Key,omitempty" json:"Key,omitempty"`
	BucketName string `xml:"BucketName,omitempty" json:"BucketName,omitempty"`
	Resource   string
	Region     string `xml:"Region,omitempty" json:"Region,omitempty"`
	RequestID  string `xml:"RequestId" json:"RequestId"`
	HostID     string `xml:"HostId" json:"HostId"`
}

// APIErrorCode type of error status.
type APIErrorCode int

//go:generate stringer -type=APIErrorCode -trimprefix=Err $GOFILE

// Error codes, non exhaustive list - http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
const (
	ErrNone APIErrorCode = iota
	ErrAccessDenied
	ErrBadDigest
	ErrEntityTooSmall
	ErrEntityTooLarge
	ErrPolicyTooLarge
	ErrIncompleteBody
	ErrInternalError
	ErrInvalidAccessKeyID
	ErrInvalidBucketName
	ErrInvalidDigest
	ErrInvalidRange
	ErrInvalidRangePartNumber
	ErrInvalidCopyPartRange
	ErrInvalidCopyPartRangeSource
	ErrInvalidMaxKeys
	ErrInvalidEncodingMethod
	ErrInvalidMaxUploads
	ErrInvalidMaxParts
	ErrInvalidPartNumberMarker
	ErrInvalidPartNumber
	ErrInvalidRequestBody
	ErrInvalidCopySource
	ErrInvalidMetadataDirective
	ErrInvalidCopyDest
	ErrInvalidPolicyDocument
	ErrInvalidObjectState
	ErrMalformedXML
	ErrMissingContentLength
	ErrMissingContentMD5
	ErrMissingRequestBodyError
	ErrMissingSecurityHeader
	ErrNoSuchCORSConfiguration
	ErrNoSuchWebsiteConfiguration
	ErrRemoteDestinationNotFoundError
	ErrRemoteTargetNotFoundError
	ErrRemoteTargetNotVersionedError
	ErrNoSuchKey
	ErrNoSuchUpload
	ErrInvalidVersionID
	ErrNoSuchVersion
	ErrNotImplemented
	ErrPreconditionFailed
	ErrRequestTimeTooSkewed
	ErrSignatureDoesNotMatch
	ErrMethodNotAllowed
	ErrInvalidPart
	ErrInvalidPartOrder
	ErrAuthorizationHeaderMalformed
	ErrMalformedPOSTRequest
	ErrPOSTFileRequired
	ErrSignatureVersionNotSupported
	ErrAllAccessDisabled
	ErrMalformedPolicy
	ErrMissingFields
	ErrMissingCredTag
	ErrCredMalformed
	ErrInvalidRegion
	ErrInvalidServiceS3
	ErrInvalidServiceSTS
	ErrInvalidRequestVersion
	ErrMissingSignTag
	ErrMissingSignHeadersTag
	ErrMalformedDate
	ErrMalformedPresignedDate
	ErrMalformedCredentialDate
	ErrMalformedCredentialRegion
	ErrMalformedExpires
	ErrNegativeExpires
	ErrAuthHeaderEmpty
	ErrExpiredPresignRequest
	ErrRequestNotReadyYet
	ErrUnsignedHeaders
	ErrMissingDateHeader
	ErrInvalidQuerySignatureAlgo
	ErrInvalidQueryParams
	ErrInvalidDuration
	ErrMetadataTooLarge
	ErrUnsupportedMetadata
	ErrMaximumExpires
	ErrSlowDown
	ErrInvalidPrefixMarker
	ErrBadRequest
	ErrKeyTooLongError
	ErrInvalidRetentionDate
	ErrUnknownWORMModeDirective
	ErrInvalidTagDirective
	ErrNoSuchACLConfiguration
	// Add new error codes here.

	// SSE-S3 related API errors
	ErrInvalidEncryptionMethod

	// Server-Side-Encryption (with Customer provided key) related API errors.
	ErrInsecureSSECustomerRequest
	ErrSSEMultipartEncrypted
	ErrInvalidEncryptionParameters
	ErrInvalidSSECustomerAlgorithm
	ErrInvalidSSECustomerKey
	ErrMissingSSECustomerKey
	ErrMissingSSECustomerKeyMD5
	ErrSSECustomerKeyMD5Mismatch
	ErrInvalidSSECustomerParameters
	ErrIncompatibleEncryptionMethod
	ErrKMSNotConfigured

	ErrNoAccessKey
	ErrInvalidToken

	// Bucket notification related errors.
	ErrEventNotification
	ErrARNNotification
	ErrRegionNotification
	ErrOverlappingFilterNotification
	ErrFilterNameInvalid
	ErrFilterNamePrefix
	ErrFilterNameSuffix
	ErrFilterValueInvalid
	ErrOverlappingConfigs
	ErrUnsupportedNotification

	// S3 extended errors.
	ErrContentSHA256Mismatch

	// Add new extended error codes here.

	// extended errors.
	ErrStorageFull
	ErrRequestBodyParse
	ErrInvalidResourceName
	ErrServerNotInitialized
	ErrOperationTimedOut
	ErrClientDisconnected
	ErrOperationMaxedOut
	ErrInvalidRequest

	ErrBackendDown

	ErrMalformedJSON
	ErrAdminNoSuchUser
	ErrAdminNoSuchGroup
	ErrAdminGroupNotEmpty
	ErrAdminNoSuchPolicy
	ErrAdminInvalidArgument
	ErrAdminInvalidAccessKey
	ErrAdminInvalidSecretKey
	ErrAdminConfigNoQuorum
	ErrAdminConfigTooLarge
	ErrAdminConfigBadJSON
	ErrAdminConfigDuplicateKeys
	ErrAdminCredentialsMismatch
	ErrInsecureClientRequest

	ErrAdminNoSuchQuotaConfiguration

	ErrHealNotImplemented
	ErrHealNoSuchProcess
	ErrHealInvalidClientToken
	ErrHealMissingBucket
	ErrHealAlreadyRunning
	ErrHealOverlappingPaths
	ErrIncorrectContinuationToken

	// S3 Select Errors
	ErrEmptyRequestBody
	ErrUnsupportedFuncion
	ErrInvalidExpressionType
	ErrBusy
	ErrUnauthorizedAccess
	ErrExpressionTooLong
	ErrIllegalSQLFunctionArgument
	ErrInvalidKeyPath
	ErrInvalidCompressionFormat
	ErrInvalidFileHeaderInfo
	ErrInvalidJSONType
	ErrInvalidQuoteFields
	ErrInvalidRequestParameter
	ErrInvalidDataType
	ErrInvalidTextEncoding
	ErrInvalidDataSource
	ErrInvalidTableAlias
	ErrMissingRequiredParameter
	ErrObjectSerializationConflict
	ErrUnsupportedSQLOperation
	ErrUnsupportedSQLStructure
	ErrUnsupportedSyntax
	ErrUnsupportedRangeHeader
	ErrLexerInvalidChar
	ErrLexerInvalidOperator
	ErrLexerInvalidLiteral
	ErrLexerInvalidIONLiteral
	ErrParseExpectedDatePart
	ErrParseExpectedKeyword
	ErrParseExpectedTokenType
	ErrParseExpected2TokenTypes
	ErrParseExpectedNumber
	ErrParseExpectedRightParenBuiltinFunctionCall
	ErrParseExpectedTypeName
	ErrParseExpectedWhenClause
	ErrParseUnsupportedToken
	ErrParseUnsupportedLiteralsGroupBy
	ErrParseExpectedMember
	ErrParseUnsupportedSelect
	ErrParseUnsupportedCase
	ErrParseUnsupportedCaseClause
	ErrParseUnsupportedAlias
	ErrParseUnsupportedSyntax
	ErrParseUnknownOperator
	ErrParseMissingIdentAfterAt
	ErrParseUnexpectedOperator
	ErrParseUnexpectedTerm
	ErrParseUnexpectedToken
	ErrParseUnexpectedKeyword
	ErrParseExpectedExpression
	ErrParseExpectedLeftParenAfterCast
	ErrParseExpectedLeftParenValueConstructor
	ErrParseExpectedLeftParenBuiltinFunctionCall
	ErrParseExpectedArgumentDelimiter
	ErrParseCastArity
	ErrParseInvalidTypeParam
	ErrParseEmptySelect
	ErrParseSelectMissingFrom
	ErrParseExpectedIdentForGroupName
	ErrParseExpectedIdentForAlias
	ErrParseUnsupportedCallWithStar
	ErrParseNonUnaryAgregateFunctionCall
	ErrParseMalformedJoin
	ErrParseExpectedIdentForAt
	ErrParseAsteriskIsNotAloneInSelectList
	ErrParseCannotMixSqbAndWildcardInSelectList
	ErrParseInvalidContextForWildcardInSelectList
	ErrIncorrectSQLFunctionArgumentType
	ErrValueParseFailure
	ErrEvaluatorInvalidArguments
	ErrIntegerOverflow
	ErrLikeInvalidInputs
	ErrCastFailed
	ErrInvalidCast
	ErrEvaluatorInvalidTimestampFormatPattern
	ErrEvaluatorInvalidTimestampFormatPatternSymbolForParsing
	ErrEvaluatorTimestampFormatPatternDuplicateFields
	ErrEvaluatorTimestampFormatPatternHourClockAmPmMismatch
	ErrEvaluatorUnterminatedTimestampFormatPatternToken
	ErrEvaluatorInvalidTimestampFormatPatternToken
	ErrEvaluatorInvalidTimestampFormatPatternSymbol
	ErrEvaluatorBindingDoesNotExist
	ErrMissingHeaders
	ErrInvalidColumnIndex

	ErrAdminConfigNotificationTargetsFailed
	ErrAdminProfilerNotEnabled
	ErrInvalidDecompressedSize
	ErrAddUserInvalidArgument
	ErrAdminAccountNotEligible
	ErrAccountNotEligible
	ErrAdminServiceAccountNotFound
	ErrPostPolicyConditionInvalidFormat
)

type errorCodeMap map[APIErrorCode]APIError

func (e errorCodeMap) ToAPIErrWithErr(errCode APIErrorCode, err error) APIError {
	apiErr, ok := e[errCode]
	if !ok {
		apiErr = e[ErrInternalError]
	}
	if err != nil {
		apiErr.Description = fmt.Sprintf("%s (%s)", apiErr.Description, err)
	}
	if globalServerRegion != "" {
		switch errCode {
		case ErrAuthorizationHeaderMalformed:
			apiErr.Description = fmt.Sprintf("The authorization header is malformed; the region is wrong; expecting '%s'.", globalServerRegion)
			return apiErr
		}
	}
	return apiErr
}

func (e errorCodeMap) ToAPIErr(errCode APIErrorCode) APIError {
	return e.ToAPIErrWithErr(errCode, nil)
}

// error code to APIError structure, these fields carry respective
// descriptions for all the error responses.
var errorCodes = errorCodeMap{
	ErrInvalidCopyDest: {
		Code:           "InvalidRequest",
		Description:    "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopySource: {
		Code:           "InvalidArgument",
		Description:    "Copy Source must mention the source bucket and key: sourcebucket/sourcekey.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMetadataDirective: {
		Code:           "InvalidArgument",
		Description:    "Unknown metadata directive.",
		HTTPStatusCode: http.StatusBadRequest,
	},

	ErrInvalidRequestBody: {
		Code:           "InvalidArgument",
		Description:    "Body shouldn't be set for this request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxUploads: {
		Code:           "InvalidArgument",
		Description:    "Argument max-uploads must be an integer between 0 and 2147483647",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxKeys: {
		Code:           "InvalidArgument",
		Description:    "Argument maxKeys must be an integer between 0 and 2147483647",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidEncodingMethod: {
		Code:           "InvalidArgument",
		Description:    "Invalid Encoding Method specified in Request",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidMaxParts: {
		Code:           "InvalidArgument",
		Description:    "Argument max-parts must be an integer between 0 and 2147483647",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartNumberMarker: {
		Code:           "InvalidArgument",
		Description:    "Argument partNumberMarker must be an integer.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartNumber: {
		Code:           "InvalidPartNumber",
		Description:    "The requested partnumber is not satisfiable",
		HTTPStatusCode: http.StatusRequestedRangeNotSatisfiable,
	},
	ErrInvalidPolicyDocument: {
		Code:           "InvalidPolicyDocument",
		Description:    "The content of the form does not meet the conditions specified in the policy document.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAccessDenied: {
		Code:           "AccessDenied",
		Description:    "Access Denied.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrBadDigest: {
		Code:           "BadDigest",
		Description:    "The Content-Md5 you specified did not match what we received.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEntityTooSmall: {
		Code:           "EntityTooSmall",
		Description:    "Your proposed upload is smaller than the minimum allowed object size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEntityTooLarge: {
		Code:           "EntityTooLarge",
		Description:    "Your proposed upload exceeds the maximum allowed object size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrPolicyTooLarge: {
		Code:           "PolicyTooLarge",
		Description:    "Policy exceeds the maximum allowed document size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrIncompleteBody: {
		Code:           "IncompleteBody",
		Description:    "You did not provide the number of bytes specified by the Content-Length HTTP header.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInternalError: {
		Code:           "InternalError",
		Description:    "We encountered an internal error, please try again.",
		HTTPStatusCode: http.StatusInternalServerError,
	},
	ErrInvalidAccessKeyID: {
		Code:           "InvalidAccessKeyId",
		Description:    "The Access Key Id you provided does not exist in our records.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidBucketName: {
		Code:           "InvalidBucketName",
		Description:    "The specified bucket is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidDigest: {
		Code:           "InvalidDigest",
		Description:    "The Content-Md5 you specified is not valid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidRange: {
		Code:           "InvalidRange",
		Description:    "The requested range is not satisfiable",
		HTTPStatusCode: http.StatusRequestedRangeNotSatisfiable,
	},
	ErrInvalidRangePartNumber: {
		Code:           "InvalidRequest",
		Description:    "Cannot specify both Range header and partNumber query parameter",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedXML: {
		Code:           "MalformedXML",
		Description:    "The XML you provided was not well-formed or did not validate against our published schema.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingContentLength: {
		Code:           "MissingContentLength",
		Description:    "You must provide the Content-Length HTTP header.",
		HTTPStatusCode: http.StatusLengthRequired,
	},
	ErrMissingContentMD5: {
		Code:           "MissingContentMD5",
		Description:    "Missing required header for this request: Content-Md5.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSecurityHeader: {
		Code:           "MissingSecurityHeader",
		Description:    "Your request was missing a required header",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingRequestBodyError: {
		Code:           "MissingRequestBodyError",
		Description:    "Request body is empty.",
		HTTPStatusCode: http.StatusLengthRequired,
	},
	ErrNoSuchKey: {
		Code:           "NoSuchKey",
		Description:    "The specified key does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchUpload: {
		Code:           "NoSuchUpload",
		Description:    "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrInvalidVersionID: {
		Code:           "InvalidArgument",
		Description:    "Invalid version id specified",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchVersion: {
		Code:           "NoSuchVersion",
		Description:    "The specified version does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNotImplemented: {
		Code:           "NotImplemented",
		Description:    "A header you provided implies functionality that is not implemented",
		HTTPStatusCode: http.StatusNotImplemented,
	},
	ErrPreconditionFailed: {
		Code:           "PreconditionFailed",
		Description:    "At least one of the pre-conditions you specified did not hold",
		HTTPStatusCode: http.StatusPreconditionFailed,
	},
	ErrRequestTimeTooSkewed: {
		Code:           "RequestTimeTooSkewed",
		Description:    "The difference between the request time and the server's time is too large.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrSignatureDoesNotMatch: {
		Code:           "SignatureDoesNotMatch",
		Description:    "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrMethodNotAllowed: {
		Code:           "MethodNotAllowed",
		Description:    "The specified method is not allowed against this resource.",
		HTTPStatusCode: http.StatusMethodNotAllowed,
	},
	ErrInvalidPart: {
		Code:           "InvalidPart",
		Description:    "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidPartOrder: {
		Code:           "InvalidPartOrder",
		Description:    "The list of parts was not in ascending order. The parts list must be specified in order by part number.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAuthorizationHeaderMalformed: {
		Code:           "AuthorizationHeaderMalformed",
		Description:    "The authorization header is malformed; the region is wrong; expecting 'us-east-1'.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedPOSTRequest: {
		Code:           "MalformedPOSTRequest",
		Description:    "The body of your POST request is not well-formed multipart/form-data.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrPOSTFileRequired: {
		Code:           "InvalidArgument",
		Description:    "POST requires exactly one file upload per request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSignatureVersionNotSupported: {
		Code:           "InvalidRequest",
		Description:    "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAllAccessDisabled: {
		Code:           "AllAccessDisabled",
		Description:    "All access to this bucket has been disabled.",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrMalformedPolicy: {
		Code:           "MalformedPolicy",
		Description:    "Policy has invalid resource.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingFields: {
		Code:           "MissingFields",
		Description:    "Missing fields in request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingCredTag: {
		Code:           "InvalidRequest",
		Description:    "Missing Credential field for this request.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrCredMalformed: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedDate: {
		Code:           "MalformedDate",
		Description:    "Invalid date format header, expected to be in ISO8601, RFC1123 or RFC1123Z time format.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedPresignedDate: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedCredentialDate: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "Error parsing the X-Amz-Credential parameter; incorrect date format. This date in the credential must be in the format \"yyyyMMdd\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidRegion: {
		Code:           "InvalidRegion",
		Description:    "Region does not match.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidServiceS3: {
		Code:           "AuthorizationParametersError",
		Description:    "Error parsing the Credential/X-Amz-Credential parameter; incorrect service. This endpoint belongs to \"s3\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidServiceSTS: {
		Code:           "AuthorizationParametersError",
		Description:    "Error parsing the Credential parameter; incorrect service. This endpoint belongs to \"sts\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidRequestVersion: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "Error parsing the X-Amz-Credential parameter; incorrect terminal. This endpoint uses \"aws4_request\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSignTag: {
		Code:           "AccessDenied",
		Description:    "Signature header missing Signature field.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSignHeadersTag: {
		Code:           "InvalidArgument",
		Description:    "Signature header missing SignedHeaders field.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMalformedExpires: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "X-Amz-Expires should be a number",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNegativeExpires: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "X-Amz-Expires must be non-negative",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAuthHeaderEmpty: {
		Code:           "InvalidArgument",
		Description:    "Authorization header is invalid -- one and only one ' ' (space) required.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingDateHeader: {
		Code:           "AccessDenied",
		Description:    "AWS authentication requires a valid Date or x-amz-date header",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidQuerySignatureAlgo: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrExpiredPresignRequest: {
		Code:           "AccessDenied",
		Description:    "Request has expired",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrRequestNotReadyYet: {
		Code:           "AccessDenied",
		Description:    "Request is not valid yet",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrSlowDown: {
		Code:           "SlowDown",
		Description:    "Resource requested is unreadable, please reduce your request rate",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrInvalidPrefixMarker: {
		Code:           "InvalidPrefixMarker",
		Description:    "Invalid marker prefix combination",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBadRequest: {
		Code:           "BadRequest",
		Description:    "400 BadRequest",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrKeyTooLongError: {
		Code:           "KeyTooLongError",
		Description:    "Your key is too long",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsignedHeaders: {
		Code:           "AccessDenied",
		Description:    "There were headers present in the request which were not signed",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidQueryParams: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.",
		HTTPStatusCode: http.StatusBadRequest,
	},

	ErrInvalidDuration: {
		Code:           "InvalidDuration",
		Description:    "Duration provided in the request is invalid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrNoSuchCORSConfiguration: {
		Code:           "NoSuchCORSConfiguration",
		Description:    "The CORS configuration does not exist",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrNoSuchWebsiteConfiguration: {
		Code:           "NoSuchWebsiteConfiguration",
		Description:    "The specified bucket does not have a website configuration",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrRemoteDestinationNotFoundError: {
		Code:           "RemoteDestinationNotFoundError",
		Description:    "The remote destination bucket does not exist",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrRemoteTargetNotFoundError: {
		Code:           "XAdminRemoteTargetNotFoundError",
		Description:    "The remote target does not exist",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrRemoteTargetNotVersionedError: {
		Code:           "RemoteTargetNotVersionedError",
		Description:    "The remote target does not have versioning enabled",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidRetentionDate: {
		Code:           "InvalidRequest",
		Description:    "Date must be provided in ISO 8601 format",
		HTTPStatusCode: http.StatusBadRequest,
	},

	ErrUnknownWORMModeDirective: {
		Code:           "InvalidRequest",
		Description:    "unknown wormMode directive",
		HTTPStatusCode: http.StatusBadRequest,
	},


	/// Bucket notification related errors.
	ErrEventNotification: {
		Code:           "InvalidArgument",
		Description:    "A specified event is not supported for notifications.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrARNNotification: {
		Code:           "InvalidArgument",
		Description:    "A specified destination ARN does not exist or is not well-formed. Verify the destination ARN.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrRegionNotification: {
		Code:           "InvalidArgument",
		Description:    "A specified destination is in a different region than the bucket. You must use a destination that resides in the same region as the bucket.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrOverlappingFilterNotification: {
		Code:           "InvalidArgument",
		Description:    "An object key name filtering rule defined with overlapping prefixes, overlapping suffixes, or overlapping combinations of prefixes and suffixes for the same event types.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrFilterNameInvalid: {
		Code:           "InvalidArgument",
		Description:    "filter rule name must be either prefix or suffix",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrFilterNamePrefix: {
		Code:           "InvalidArgument",
		Description:    "Cannot specify more than one prefix rule in a filter.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrFilterNameSuffix: {
		Code:           "InvalidArgument",
		Description:    "Cannot specify more than one suffix rule in a filter.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrFilterValueInvalid: {
		Code:           "InvalidArgument",
		Description:    "Size of filter rule value cannot exceed 1024 bytes in UTF-8 representation",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrOverlappingConfigs: {
		Code:           "InvalidArgument",
		Description:    "Configurations overlap. Configurations on the same bucket cannot share a common event type.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedNotification: {
		Code:           "UnsupportedNotification",
		Description:    "server does not support Topic or Cloud Function based notifications.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopyPartRange: {
		Code:           "InvalidArgument",
		Description:    "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCopyPartRangeSource: {
		Code:           "InvalidArgument",
		Description:    "Range specified is not valid for source object",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMetadataTooLarge: {
		Code:           "MetadataTooLarge",
		Description:    "Your metadata headers exceed the maximum allowed metadata size.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTagDirective: {
		Code:           "InvalidArgument",
		Description:    "Unknown tag directive.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidEncryptionMethod: {
		Code:           "InvalidRequest",
		Description:    "The encryption method specified is not supported",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInsecureSSECustomerRequest: {
		Code:           "InvalidRequest",
		Description:    "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSSEMultipartEncrypted: {
		Code:           "InvalidRequest",
		Description:    "The multipart upload initiate requested encryption. Subsequent part requests must include the appropriate encryption parameters.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidEncryptionParameters: {
		Code:           "InvalidRequest",
		Description:    "The encryption parameters are not applicable to this object.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidSSECustomerAlgorithm: {
		Code:           "InvalidArgument",
		Description:    "Requests specifying Server Side Encryption with Customer provided keys must provide a valid encryption algorithm.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidSSECustomerKey: {
		Code:           "InvalidArgument",
		Description:    "The secret key was invalid for the specified algorithm.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSSECustomerKey: {
		Code:           "InvalidArgument",
		Description:    "Requests specifying Server Side Encryption with Customer provided keys must provide an appropriate secret key.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingSSECustomerKeyMD5: {
		Code:           "InvalidArgument",
		Description:    "Requests specifying Server Side Encryption with Customer provided keys must provide the client calculated MD5 of the secret key.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrSSECustomerKeyMD5Mismatch: {
		Code:           "InvalidArgument",
		Description:    "The calculated MD5 hash of the key did not match the hash that was provided.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidSSECustomerParameters: {
		Code:           "InvalidArgument",
		Description:    "The provided encryption parameters did not match the ones used originally.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrIncompatibleEncryptionMethod: {
		Code:           "InvalidArgument",
		Description:    "Server side encryption specified with both SSE-C and SSE-S3 headers",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrKMSNotConfigured: {
		Code:           "NotImplemented",
		Description:    "Server side encryption specified but KMS is not configured",
		HTTPStatusCode: http.StatusNotImplemented,
	},
	ErrNoAccessKey: {
		Code:           "AccessDenied",
		Description:    "No AWSAccessKey was presented",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrInvalidToken: {
		Code:           "InvalidTokenId",
		Description:    "The security token included in the request is invalid",
		HTTPStatusCode: http.StatusForbidden,
	},

	/// S3 extensions.
	ErrContentSHA256Mismatch: {
		Code:           "XAmzContentSHA256Mismatch",
		Description:    "The provided 'x-amz-content-sha256' header does not match what was computed.",
		HTTPStatusCode: http.StatusBadRequest,
	},

	///  extensions.
	ErrStorageFull: {
		Code:           "XStorageFull",
		Description:    "Storage backend has reached its minimum free disk threshold. Please delete a few objects to proceed.",
		HTTPStatusCode: http.StatusInsufficientStorage,
	},
	ErrRequestBodyParse: {
		Code:           "XRequestBodyParse",
		Description:    "The request body failed to parse.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidResourceName: {
		Code:           "XInvalidResourceName",
		Description:    "Resource name contains bad components such as \"..\" or \".\".",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrServerNotInitialized: {
		Code:           "XServerNotInitialized",
		Description:    "Server not initialized, please try again.",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrMalformedJSON: {
		Code:           "XMalformedJSON",
		Description:    "The JSON you provided was not well-formed or did not validate against our published format.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminNoSuchUser: {
		Code:           "XAdminNoSuchUser",
		Description:    "The specified user does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrAdminNoSuchGroup: {
		Code:           "XAdminNoSuchGroup",
		Description:    "The specified group does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrAdminGroupNotEmpty: {
		Code:           "XAdminGroupNotEmpty",
		Description:    "The specified group is not empty - cannot remove it.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminNoSuchPolicy: {
		Code:           "XAdminNoSuchPolicy",
		Description:    "The canned policy does not exist.",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrAdminInvalidArgument: {
		Code:           "XAdminInvalidArgument",
		Description:    "Invalid arguments specified.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminInvalidAccessKey: {
		Code:           "XAdminInvalidAccessKey",
		Description:    "The access key is invalid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminInvalidSecretKey: {
		Code:           "XAdminInvalidSecretKey",
		Description:    "The secret key is invalid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminConfigNoQuorum: {
		Code:           "XAdminConfigNoQuorum",
		Description:    "Configuration update failed because server quorum was not met",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrAdminConfigTooLarge: {
		Code: "XAdminConfigTooLarge",
		Description: fmt.Sprintf("Configuration data provided exceeds the allowed maximum of %d bytes",
			maxEConfigJSONSize),
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminConfigBadJSON: {
		Code:           "XAdminConfigBadJSON",
		Description:    "JSON configuration provided is of incorrect format",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminConfigDuplicateKeys: {
		Code:           "XAdminConfigDuplicateKeys",
		Description:    "JSON configuration provided has objects with duplicate keys",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminConfigNotificationTargetsFailed: {
		Code:           "XAdminNotificationTargetsTestFailed",
		Description:    "Configuration update failed due an unsuccessful attempt to connect to one or more notification servers",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminProfilerNotEnabled: {
		Code:           "XAdminProfilerNotEnabled",
		Description:    "Unable to perform the requested operation because profiling is not enabled",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAdminCredentialsMismatch: {
		Code:           "XAdminCredentialsMismatch",
		Description:    "Credentials in config mismatch with server environment variables",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrAdminNoSuchQuotaConfiguration: {
		Code:           "XAdminNoSuchQuotaConfiguration",
		Description:    "The quota configuration does not exist",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrInsecureClientRequest: {
		Code:           "XInsecureClientRequest",
		Description:    "Cannot respond to plain-text request from TLS-encrypted server",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrOperationTimedOut: {
		Code:           "RequestTimeout",
		Description:    "A timeout occurred while trying to lock a resource, please reduce your request rate",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrClientDisconnected: {
		Code:           "ClientDisconnected",
		Description:    "Client disconnected before response was ready",
		HTTPStatusCode: 499, // No official code, use nginx value.
	},
	ErrOperationMaxedOut: {
		Code:           "SlowDown",
		Description:    "A timeout exceeded while waiting to proceed with the request, please reduce your request rate",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrUnsupportedMetadata: {
		Code:           "InvalidArgument",
		Description:    "Your metadata headers are not supported.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMaximumExpires: {
		Code:           "AuthorizationQueryParametersError",
		Description:    "X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires must be less than 604800 seconds",
		HTTPStatusCode: http.StatusBadRequest,
	},

	// Generic Invalid-Request error. Should be used for response errors only for unlikely
	// corner case errors for which introducing new APIErrorCode is not worth it. LogIf()
	// should be used to log the error at the source of the error for debugging purposes.
	ErrInvalidRequest: {
		Code:           "InvalidRequest",
		Description:    "Invalid Request",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrHealNotImplemented: {
		Code:           "XHealNotImplemented",
		Description:    "This server does not implement heal functionality.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrHealNoSuchProcess: {
		Code:           "XHealNoSuchProcess",
		Description:    "No such heal process is running on the server",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrHealInvalidClientToken: {
		Code:           "XHealInvalidClientToken",
		Description:    "Client token mismatch",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrHealMissingBucket: {
		Code:           "XHealMissingBucket",
		Description:    "A heal start request with a non-empty object-prefix parameter requires a bucket to be specified.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrHealAlreadyRunning: {
		Code:           "XHealAlreadyRunning",
		Description:    "",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrHealOverlappingPaths: {
		Code:           "XHealOverlappingPaths",
		Description:    "",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBackendDown: {
		Code:           "XBackendDown",
		Description:    "Object storage backend is unreachable",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrIncorrectContinuationToken: {
		Code:           "InvalidArgument",
		Description:    "The continuation token provided is incorrect",
		HTTPStatusCode: http.StatusBadRequest,
	},
	//S3 Select API Errors
	ErrEmptyRequestBody: {
		Code:           "EmptyRequestBody",
		Description:    "Request body cannot be empty.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidDataSource: {
		Code:           "InvalidDataSource",
		Description:    "Invalid data source type. Only CSV and JSON are supported at this time.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidExpressionType: {
		Code:           "InvalidExpressionType",
		Description:    "The ExpressionType is invalid. Only SQL expressions are supported at this time.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrBusy: {
		Code:           "Busy",
		Description:    "The service is unavailable. Please retry.",
		HTTPStatusCode: http.StatusServiceUnavailable,
	},
	ErrUnauthorizedAccess: {
		Code:           "UnauthorizedAccess",
		Description:    "You are not authorized to perform this operation",
		HTTPStatusCode: http.StatusUnauthorized,
	},
	ErrExpressionTooLong: {
		Code:           "ExpressionTooLong",
		Description:    "The SQL expression is too long: The maximum byte-length for the SQL expression is 256 KB.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrIllegalSQLFunctionArgument: {
		Code:           "IllegalSqlFunctionArgument",
		Description:    "Illegal argument was used in the SQL function.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidKeyPath: {
		Code:           "InvalidKeyPath",
		Description:    "Key path in the SQL expression is invalid.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCompressionFormat: {
		Code:           "InvalidCompressionFormat",
		Description:    "The file is not in a supported compression format. Only GZIP is supported at this time.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidFileHeaderInfo: {
		Code:           "InvalidFileHeaderInfo",
		Description:    "The FileHeaderInfo is invalid. Only NONE, USE, and IGNORE are supported.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidJSONType: {
		Code:           "InvalidJsonType",
		Description:    "The JsonType is invalid. Only DOCUMENT and LINES are supported at this time.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidQuoteFields: {
		Code:           "InvalidQuoteFields",
		Description:    "The QuoteFields is invalid. Only ALWAYS and ASNEEDED are supported.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidRequestParameter: {
		Code:           "InvalidRequestParameter",
		Description:    "The value of a parameter in SelectRequest element is invalid. Check the service API documentation and try again.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidDataType: {
		Code:           "InvalidDataType",
		Description:    "The SQL expression contains an invalid data type.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTextEncoding: {
		Code:           "InvalidTextEncoding",
		Description:    "Invalid encoding type. Only UTF-8 encoding is supported at this time.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidTableAlias: {
		Code:           "InvalidTableAlias",
		Description:    "The SQL expression contains an invalid table alias.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingRequiredParameter: {
		Code:           "MissingRequiredParameter",
		Description:    "The SelectRequest entity is missing a required parameter. Check the service documentation and try again.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrObjectSerializationConflict: {
		Code:           "ObjectSerializationConflict",
		Description:    "The SelectRequest entity can only contain one of CSV or JSON. Check the service documentation and try again.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedSQLOperation: {
		Code:           "UnsupportedSqlOperation",
		Description:    "Encountered an unsupported SQL operation.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedSQLStructure: {
		Code:           "UnsupportedSqlStructure",
		Description:    "Encountered an unsupported SQL structure. Check the SQL Reference.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedSyntax: {
		Code:           "UnsupportedSyntax",
		Description:    "Encountered invalid syntax.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrUnsupportedRangeHeader: {
		Code:           "UnsupportedRangeHeader",
		Description:    "Range header is not supported for this operation.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrLexerInvalidChar: {
		Code:           "LexerInvalidChar",
		Description:    "The SQL expression contains an invalid character.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrLexerInvalidOperator: {
		Code:           "LexerInvalidOperator",
		Description:    "The SQL expression contains an invalid literal.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrLexerInvalidLiteral: {
		Code:           "LexerInvalidLiteral",
		Description:    "The SQL expression contains an invalid operator.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrLexerInvalidIONLiteral: {
		Code:           "LexerInvalidIONLiteral",
		Description:    "The SQL expression contains an invalid operator.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedDatePart: {
		Code:           "ParseExpectedDatePart",
		Description:    "Did not find the expected date part in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedKeyword: {
		Code:           "ParseExpectedKeyword",
		Description:    "Did not find the expected keyword in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedTokenType: {
		Code:           "ParseExpectedTokenType",
		Description:    "Did not find the expected token in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpected2TokenTypes: {
		Code:           "ParseExpected2TokenTypes",
		Description:    "Did not find the expected token in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedNumber: {
		Code:           "ParseExpectedNumber",
		Description:    "Did not find the expected number in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedRightParenBuiltinFunctionCall: {
		Code:           "ParseExpectedRightParenBuiltinFunctionCall",
		Description:    "Did not find the expected right parenthesis character in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedTypeName: {
		Code:           "ParseExpectedTypeName",
		Description:    "Did not find the expected type name in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedWhenClause: {
		Code:           "ParseExpectedWhenClause",
		Description:    "Did not find the expected WHEN clause in the SQL expression. CASE is not supported.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedToken: {
		Code:           "ParseUnsupportedToken",
		Description:    "The SQL expression contains an unsupported token.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedLiteralsGroupBy: {
		Code:           "ParseUnsupportedLiteralsGroupBy",
		Description:    "The SQL expression contains an unsupported use of GROUP BY.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedMember: {
		Code:           "ParseExpectedMember",
		Description:    "The SQL expression contains an unsupported use of MEMBER.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedSelect: {
		Code:           "ParseUnsupportedSelect",
		Description:    "The SQL expression contains an unsupported use of SELECT.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedCase: {
		Code:           "ParseUnsupportedCase",
		Description:    "The SQL expression contains an unsupported use of CASE.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedCaseClause: {
		Code:           "ParseUnsupportedCaseClause",
		Description:    "The SQL expression contains an unsupported use of CASE.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedAlias: {
		Code:           "ParseUnsupportedAlias",
		Description:    "The SQL expression contains an unsupported use of ALIAS.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedSyntax: {
		Code:           "ParseUnsupportedSyntax",
		Description:    "The SQL expression contains unsupported syntax.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnknownOperator: {
		Code:           "ParseUnknownOperator",
		Description:    "The SQL expression contains an invalid operator.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseMissingIdentAfterAt: {
		Code:           "ParseMissingIdentAfterAt",
		Description:    "Did not find the expected identifier after the @ symbol in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnexpectedOperator: {
		Code:           "ParseUnexpectedOperator",
		Description:    "The SQL expression contains an unexpected operator.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnexpectedTerm: {
		Code:           "ParseUnexpectedTerm",
		Description:    "The SQL expression contains an unexpected term.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnexpectedToken: {
		Code:           "ParseUnexpectedToken",
		Description:    "The SQL expression contains an unexpected token.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnexpectedKeyword: {
		Code:           "ParseUnexpectedKeyword",
		Description:    "The SQL expression contains an unexpected keyword.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedExpression: {
		Code:           "ParseExpectedExpression",
		Description:    "Did not find the expected SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedLeftParenAfterCast: {
		Code:           "ParseExpectedLeftParenAfterCast",
		Description:    "Did not find expected the left parenthesis in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedLeftParenValueConstructor: {
		Code:           "ParseExpectedLeftParenValueConstructor",
		Description:    "Did not find expected the left parenthesis in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedLeftParenBuiltinFunctionCall: {
		Code:           "ParseExpectedLeftParenBuiltinFunctionCall",
		Description:    "Did not find the expected left parenthesis in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedArgumentDelimiter: {
		Code:           "ParseExpectedArgumentDelimiter",
		Description:    "Did not find the expected argument delimiter in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseCastArity: {
		Code:           "ParseCastArity",
		Description:    "The SQL expression CAST has incorrect arity.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseInvalidTypeParam: {
		Code:           "ParseInvalidTypeParam",
		Description:    "The SQL expression contains an invalid parameter value.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseEmptySelect: {
		Code:           "ParseEmptySelect",
		Description:    "The SQL expression contains an empty SELECT.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseSelectMissingFrom: {
		Code:           "ParseSelectMissingFrom",
		Description:    "GROUP is not supported in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedIdentForGroupName: {
		Code:           "ParseExpectedIdentForGroupName",
		Description:    "GROUP is not supported in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedIdentForAlias: {
		Code:           "ParseExpectedIdentForAlias",
		Description:    "Did not find the expected identifier for the alias in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseUnsupportedCallWithStar: {
		Code:           "ParseUnsupportedCallWithStar",
		Description:    "Only COUNT with (*) as a parameter is supported in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseNonUnaryAgregateFunctionCall: {
		Code:           "ParseNonUnaryAgregateFunctionCall",
		Description:    "Only one argument is supported for aggregate functions in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseMalformedJoin: {
		Code:           "ParseMalformedJoin",
		Description:    "JOIN is not supported in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseExpectedIdentForAt: {
		Code:           "ParseExpectedIdentForAt",
		Description:    "Did not find the expected identifier for AT name in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseAsteriskIsNotAloneInSelectList: {
		Code:           "ParseAsteriskIsNotAloneInSelectList",
		Description:    "Other expressions are not allowed in the SELECT list when '*' is used without dot notation in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseCannotMixSqbAndWildcardInSelectList: {
		Code:           "ParseCannotMixSqbAndWildcardInSelectList",
		Description:    "Cannot mix [] and * in the same expression in a SELECT list in SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrParseInvalidContextForWildcardInSelectList: {
		Code:           "ParseInvalidContextForWildcardInSelectList",
		Description:    "Invalid use of * in SELECT list in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrIncorrectSQLFunctionArgumentType: {
		Code:           "IncorrectSqlFunctionArgumentType",
		Description:    "Incorrect type of arguments in function call in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrValueParseFailure: {
		Code:           "ValueParseFailure",
		Description:    "Time stamp parse failure in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorInvalidArguments: {
		Code:           "EvaluatorInvalidArguments",
		Description:    "Incorrect number of arguments in the function call in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrIntegerOverflow: {
		Code:           "IntegerOverflow",
		Description:    "Int overflow or underflow in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrLikeInvalidInputs: {
		Code:           "LikeInvalidInputs",
		Description:    "Invalid argument given to the LIKE clause in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrCastFailed: {
		Code:           "CastFailed",
		Description:    "Attempt to convert from one data type to another using CAST failed in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidCast: {
		Code:           "InvalidCast",
		Description:    "Attempt to convert from one data type to another using CAST failed in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorInvalidTimestampFormatPattern: {
		Code:           "EvaluatorInvalidTimestampFormatPattern",
		Description:    "Time stamp format pattern requires additional fields in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorInvalidTimestampFormatPatternSymbolForParsing: {
		Code:           "EvaluatorInvalidTimestampFormatPatternSymbolForParsing",
		Description:    "Time stamp format pattern contains a valid format symbol that cannot be applied to time stamp parsing in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorTimestampFormatPatternDuplicateFields: {
		Code:           "EvaluatorTimestampFormatPatternDuplicateFields",
		Description:    "Time stamp format pattern contains multiple format specifiers representing the time stamp field in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorTimestampFormatPatternHourClockAmPmMismatch: {
		Code:           "EvaluatorUnterminatedTimestampFormatPatternToken",
		Description:    "Time stamp format pattern contains unterminated token in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorUnterminatedTimestampFormatPatternToken: {
		Code:           "EvaluatorInvalidTimestampFormatPatternToken",
		Description:    "Time stamp format pattern contains an invalid token in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorInvalidTimestampFormatPatternToken: {
		Code:           "EvaluatorInvalidTimestampFormatPatternToken",
		Description:    "Time stamp format pattern contains an invalid token in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorInvalidTimestampFormatPatternSymbol: {
		Code:           "EvaluatorInvalidTimestampFormatPatternSymbol",
		Description:    "Time stamp format pattern contains an invalid symbol in the SQL expression.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrEvaluatorBindingDoesNotExist: {
		Code:           "ErrEvaluatorBindingDoesNotExist",
		Description:    "A column name or a path provided does not exist in the SQL expression",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrMissingHeaders: {
		Code:           "MissingHeaders",
		Description:    "Some headers in the query are missing from the file. Check the file and try again.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidColumnIndex: {
		Code:           "InvalidColumnIndex",
		Description:    "The column index is invalid. Please check the service documentation and try again.",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrInvalidDecompressedSize: {
		Code:           "XInvalidDecompressedSize",
		Description:    "The data provided is unfit for decompression",
		HTTPStatusCode: http.StatusBadRequest,
	},
	ErrAddUserInvalidArgument: {
		Code:           "XInvalidIAMCredentials",
		Description:    "User is not allowed to be same as admin access key",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAdminAccountNotEligible: {
		Code:           "XInvalidIAMCredentials",
		Description:    "The administrator key is not eligible for this operation",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAccountNotEligible: {
		Code:           "XInvalidIAMCredentials",
		Description:    "The account key is not eligible for this operation",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrAdminServiceAccountNotFound: {
		Code:           "XInvalidIAMCredentials",
		Description:    "The specified service account is not found",
		HTTPStatusCode: http.StatusNotFound,
	},
	ErrPostPolicyConditionInvalidFormat: {
		Code:           "PostPolicyInvalidKeyName",
		Description:    "Invalid according to Policy: Policy Condition failed",
		HTTPStatusCode: http.StatusForbidden,
	},
	ErrNoSuchACLConfiguration: {
		Code:           "NoSuchAclSet",
		Description:    "The AclSet does not exist",
		HTTPStatusCode: http.StatusNotFound,
	},
	// Add your error structure here.
}

// toAPIErrorCode - Converts embedded errors. Convenience
// function written to handle all cases where we have known types of
// errors returned by underlying layers.
func toAPIErrorCode(ctx context.Context, err error) (apiErr APIErrorCode) {
	if err == nil {
		return ErrNone
	}

	// Only return ErrClientDisconnected if the provided context is actually canceled.
	// This way downstream context.Canceled will still report ErrOperationTimedOut
	select {
	case <-ctx.Done():
		if ctx.Err() == context.Canceled {
			return ErrClientDisconnected
		}
	default:
	}

	switch err {
	case errInvalidArgument:
		apiErr = ErrAdminInvalidArgument
	case errNoSuchUser:
		apiErr = ErrAdminNoSuchUser
	case errNoSuchServiceAccount:
		apiErr = ErrAdminServiceAccountNotFound
	case errNoSuchGroup:
		apiErr = ErrAdminNoSuchGroup
	case errGroupNotEmpty:
		apiErr = ErrAdminGroupNotEmpty
	case errNoSuchPolicy:
		apiErr = ErrAdminNoSuchPolicy
	case errSignatureMismatch:
		apiErr = ErrSignatureDoesNotMatch
	case errInvalidRange:
		apiErr = ErrInvalidRange
	case errDataTooLarge:
		apiErr = ErrEntityTooLarge
	case errDataTooSmall:
		apiErr = ErrEntityTooSmall
	case errAuthentication:
		apiErr = ErrAccessDenied
	case auth.ErrInvalidAccessKeyLength:
		apiErr = ErrAdminInvalidAccessKey
	case auth.ErrInvalidSecretKeyLength:
		apiErr = ErrAdminInvalidSecretKey
	// SSE errors
	case errInvalidEncryptionParameters:
		apiErr = ErrInvalidEncryptionParameters
	case crypto.ErrInvalidEncryptionMethod:
		apiErr = ErrInvalidEncryptionMethod
	case crypto.ErrInvalidCustomerAlgorithm:
		apiErr = ErrInvalidSSECustomerAlgorithm
	case crypto.ErrMissingCustomerKey:
		apiErr = ErrMissingSSECustomerKey
	case crypto.ErrMissingCustomerKeyMD5:
		apiErr = ErrMissingSSECustomerKeyMD5
	case crypto.ErrCustomerKeyMD5Mismatch:
		apiErr = ErrSSECustomerKeyMD5Mismatch
	case errInvalidSSEParameters:
		apiErr = ErrInvalidSSECustomerParameters
	case crypto.ErrInvalidCustomerKey, crypto.ErrSecretKeyMismatch:
		apiErr = ErrAccessDenied // no access without correct key
	case crypto.ErrIncompatibleEncryptionMethod:
		apiErr = ErrIncompatibleEncryptionMethod
	case errKMSNotConfigured:
		apiErr = ErrKMSNotConfigured
	case context.Canceled, context.DeadlineExceeded:
		apiErr = ErrOperationTimedOut
	case errDiskNotFound:
		apiErr = ErrSlowDown
	}

	// Compression errors
	switch err {
	case errInvalidDecompressedSize:
		apiErr = ErrInvalidDecompressedSize
	}

	if apiErr != ErrNone {
		// If there was a match in the above switch case.
		return apiErr
	}

	switch err.(type) {
	case StorageFull:
		apiErr = ErrStorageFull
	case hash.BadDigest:
		apiErr = ErrBadDigest
	case AllAccessDisabled:
		apiErr = ErrAllAccessDisabled
	case IncompleteBody:
		apiErr = ErrIncompleteBody
	case PrefixAccessDenied:
		apiErr = ErrAccessDenied
	case BucketNameInvalid:
		apiErr = ErrInvalidBucketName
	case ObjectNotFound:
		apiErr = ErrNoSuchKey
	case MethodNotAllowed:
		apiErr = ErrMethodNotAllowed
	case InvalidVersionID:
		apiErr = ErrInvalidVersionID
	case VersionNotFound:
		apiErr = ErrNoSuchVersion
	case ObjectAlreadyExists:
		apiErr = ErrMethodNotAllowed
	case InvalidUploadID:
		apiErr = ErrNoSuchUpload
	case InvalidPart:
		apiErr = ErrInvalidPart
	case InsufficientWriteQuorum:
		apiErr = ErrSlowDown
	case InsufficientReadQuorum:
		apiErr = ErrSlowDown
	case InvalidMarkerPrefixCombination:
		apiErr = ErrNotImplemented
	case InvalidUploadIDKeyCombination:
		apiErr = ErrNotImplemented
	case MalformedUploadID:
		apiErr = ErrNoSuchUpload
	case PartTooSmall:
		apiErr = ErrEntityTooSmall
	case SignatureDoesNotMatch:
		apiErr = ErrSignatureDoesNotMatch
	case hash.SHA256Mismatch:
		apiErr = ErrContentSHA256Mismatch
	case ObjectTooLarge:
		apiErr = ErrEntityTooLarge
	case ObjectTooSmall:
		apiErr = ErrEntityTooSmall
	case NotImplemented:
		apiErr = ErrNotImplemented
	case PartTooBig:
		apiErr = ErrEntityTooLarge
	case UnsupportedMetadata:
		apiErr = ErrUnsupportedMetadata

	case InvalidObjectState:
		apiErr = ErrInvalidObjectState
	case *event.ErrInvalidEventName:
		apiErr = ErrEventNotification
	case *event.ErrInvalidARN:
		apiErr = ErrARNNotification
	case *event.ErrARNNotFound:
		apiErr = ErrARNNotification
	case *event.ErrUnknownRegion:
		apiErr = ErrRegionNotification
	case *event.ErrInvalidFilterName:
		apiErr = ErrFilterNameInvalid
	case *event.ErrFilterNamePrefix:
		apiErr = ErrFilterNamePrefix
	case *event.ErrFilterNameSuffix:
		apiErr = ErrFilterNameSuffix
	case *event.ErrInvalidFilterValue:
		apiErr = ErrFilterValueInvalid
	case *event.ErrDuplicateEventName:
		apiErr = ErrOverlappingConfigs
	case *event.ErrDuplicateQueueConfiguration:
		apiErr = ErrOverlappingFilterNotification
	case *event.ErrUnsupportedConfiguration:
		apiErr = ErrUnsupportedNotification
	case OperationTimedOut:
		apiErr = ErrOperationTimedOut
	case BackendDown:
		apiErr = ErrBackendDown
	case ObjectNameTooLong:
		apiErr = ErrKeyTooLongError
	default:
		var ie, iw int
		// This work-around is to handle the issue golang/go#30648
		if _, ferr := fmt.Fscanf(strings.NewReader(err.Error()),
			"request declared a Content-Length of %d but only wrote %d bytes",
			&ie, &iw); ferr != nil {
			apiErr = ErrInternalError
			// Make sure to log the errors which we cannot translate
			// to a meaningful S3 API errors. This is added to aid in
			// debugging unexpected/unhandled errors.
			logger.LogIf(ctx, err)
		} else if ie > iw {
			apiErr = ErrIncompleteBody
		} else {
			apiErr = ErrInternalError
			// Make sure to log the errors which we cannot translate
			// to a meaningful S3 API errors. This is added to aid in
			// debugging unexpected/unhandled errors.
			logger.LogIf(ctx, err)
		}
	}

	return apiErr
}

var noError = APIError{}

// getAPIError provides API Error for input API error code.
func getAPIError(code APIErrorCode) APIError {
	if apiErr, ok := errorCodes[code]; ok {
		return apiErr
	}
	return errorCodes.ToAPIErr(ErrInternalError)
}

// getErrorResponse gets in standard error and resource value and
// provides a encodable populated response values
func getAPIErrorResponse(ctx context.Context, err APIError, resource, requestID, hostID string) APIErrorResponse {
	reqInfo := logger.GetReqInfo(ctx)
	return APIErrorResponse{
		Code:       err.Code,
		Message:    err.Description,
		BucketName: reqInfo.BucketName,
		Key:        reqInfo.ObjectName,
		Resource:   resource,
		Region:     globalServerRegion,
		RequestID:  requestID,
		HostID:     hostID,
	}
}
