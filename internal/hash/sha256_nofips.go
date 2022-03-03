

//go:build !fips
// +build !fips

package hash

import (
	"hash"

	sha256 "github.com/minio/sha256-simd"
)

// newSHA256 returns a new hash.Hash computing the SHA256 checksum.
// The SHA256 implementation is not FIPS 140-2 compliant.
func newSHA256() hash.Hash { return sha256.New() }
