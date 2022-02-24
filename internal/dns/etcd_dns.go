package dns

import "errors"

// ErrNoEntriesFound - Indicates no entries were found for the given key (directory)
var ErrNoEntriesFound = errors.New("No entries found for this key")

// ErrDomainMissing - Indicates domain is missing
var ErrDomainMissing = errors.New("domain is missing")
