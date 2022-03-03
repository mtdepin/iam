package http

// Standard S3 HTTP response constants
const (
	LastModified       = "Last-Modified"
	Date               = "Date"
	ETag               = "ETag"
	StorageClass       = "StorageClass"
	ContentType        = "Content-Type"
	ContentMD5         = "Content-Md5"
	ContentEncoding    = "Content-Encoding"
	Expires            = "Expires"
	ContentLength      = "Content-Length"
	ContentLanguage    = "Content-Language"
	ContentRange       = "Content-Range"
	Connection         = "Connection"
	AcceptRanges       = "Accept-Ranges"
	AmzBucketRegion    = "X-Amz-Bucket-Region"
	ServerInfo         = "Server"
	RetryAfter         = "Retry-After"
	Location           = "Location"
	CacheControl       = "Cache-Control"
	ContentDisposition = "Content-Disposition"
	Authorization      = "Authorization"
	Action             = "Action"
	Range              = "Range"
)

// Non standard S3 HTTP response constants
const (
	XCache       = "X-Cache"
	XCacheLookup = "X-Cache-Lookup"
)

// Standard S3 HTTP request constants
const (
	// S3 storage class
	AmzStorageClass = "x-amz-storage-class"

	// S3 object tagging
	AmzObjectTagging = "X-Amz-Tagging"

	AmzCopySource                = "X-Amz-Copy-Source"
	AmzObjectLockMode            = "X-Amz-Object-Lock-Mode"
	AmzObjectLockRetainUntilDate = "X-Amz-Object-Lock-Retain-Until-Date"
	AmzObjectLockLegalHold       = "X-Amz-Object-Lock-Legal-Hold"
	AmzBucketReplicationStatus   = "X-Amz-Replication-Status"

	// Signature V4 related contants.
	AmzContentSha256 = "X-Amz-Content-Sha256"
	AmzDate          = "X-Amz-Date"
	AmzAlgorithm     = "X-Amz-Algorithm"
	AmzExpires       = "X-Amz-Expires"
	AmzSignedHeaders = "X-Amz-SignedHeaders"
	AmzSignature     = "X-Amz-Signature"
	AmzCredential    = "X-Amz-Credential"
	AmzSecurityToken = "X-Amz-Security-Token"

	AmzMetaUnencryptedContentLength = "X-Amz-Meta-X-Amz-Unencrypted-Content-Length"
	AmzMetaUnencryptedContentMD5    = "X-Amz-Meta-X-Amz-Unencrypted-Content-Md5"

	// AWS server-side encryption headers for SSE-S3, SSE-KMS and SSE-C.
	AmzServerSideEncryption                      = "X-Amz-Server-Side-Encryption"
	AmzServerSideEncryptionCustomerKey           = AmzServerSideEncryption + "-Customer-Key"
	AmzServerSideEncryptionCopyCustomerAlgorithm = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm"
	AmzServerSideEncryptionCopyCustomerKey       = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"
	AmzServerSideEncryptionCopyCustomerKeyMD5    = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5"

	AmzEncryptionAES = "AES256"
	AmzEncryptionKMS = "aws:kms"

	// Signature v2 related constants
	AmzSignatureV2 = "Signature"
	AmzAccessKeyID = "AWSAccessKeyId"

	// Response request id.
	AmzRequestID = "x-amz-request-id"

	// Deployment id.
	MinioDeploymentID = "x-minio-deployment-id"

	// Header indicates that this request is a replication request to create a REPLICA
	MinIOSourceReplicationRequest = "X-Minio-Source-Replication-Request"
)

// Common http query params S3 API
const (
	VersionID = "versionId"

	PartNumber = "partNumber"

	UploadID = "uploadId"
)
