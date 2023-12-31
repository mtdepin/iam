package internal

import "errors"

// errInvalidArgument means that input argument is invalid.
var errInvalidArgument = errors.New("Invalid arguments specified")

// errMethodNotAllowed means that method is not allowed.
var errMethodNotAllowed = errors.New("Method not allowed")

// errSignatureMismatch means signature did not match.
var errSignatureMismatch = errors.New("Signature does not match")

// used when we deal with data larger than expected
var errSizeUnexpected = errors.New("Data size larger than expected")

// When upload object size is greater than 5G in a single PUT/POST operation.
var errDataTooLarge = errors.New("Object size larger than allowed limit")

// When upload object size is less than what was expected.
var errDataTooSmall = errors.New("Object size smaller than expected")

// errServerNotInitialized - server not initialized.
var errServerNotInitialized = errors.New("Server not initialized, please try again")

// errRPCAPIVersionUnsupported - unsupported rpc API version.
var errRPCAPIVersionUnsupported = errors.New("Unsupported rpc API version")

// errServerTimeMismatch - server times are too far apart.
var errServerTimeMismatch = errors.New("Server times are too far apart")

// errInvalidRange - returned when given range value is not valid.
var errInvalidRange = errors.New("Invalid range")

// errInvalidRangeSource - returned when given range value exceeds
// the source object size.
var errInvalidRangeSource = errors.New("Range specified exceeds source object size")

// error returned by disks which are to be initialized are waiting for the
// first server to initialize them in distributed set to initialize them.
var errNotFirstDisk = errors.New("Not first disk")

// error returned by first disk waiting to initialize other servers.
var errFirstDiskWait = errors.New("Waiting on other disks")

// error returned for a negative actual size.
var errInvalidDecompressedSize = errors.New("Invalid Decompressed Size")

// error returned in IAM subsystem when user doesn't exist.
var errNoSuchUser = errors.New("Specified user does not exist")

// error returned when service account is not found
var errNoSuchServiceAccount = errors.New("Specified service account does not exist")
var errNotAllowed = errors.New("This account cannot be deleted")

// error returned in IAM subsystem when groups doesn't exist.
var errNoSuchGroup = errors.New("Specified group does not exist")
var errSkipFile = errors.New("skip this file")

// error returned in IAM subsystem when a non-empty group needs to be
// deleted.
var errGroupNotEmpty = errors.New("Specified group is not empty - cannot remove it")

// error returned in IAM subsystem when policy doesn't exist.
var errNoSuchPolicy = errors.New("Specified canned policy does not exist")

// error returned in IAM subsystem when an external users systems is configured.
var errIAMActionNotAllowed = errors.New("Specified IAM action is not allowed with LDAP configuration")

// error returned in IAM subsystem when IAM sub-system is still being initialized.
var errIAMNotInitialized = errors.New("IAM sub-system is being initialized, please try again")

// error returned when upload id not found
var errUploadIDNotFound = errors.New("Specified Upload ID is not found")
