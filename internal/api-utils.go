package internal

import (
	"crypto/sha1"
	"fmt"
)

const (
	//密钥
	Key = "mtyw123*7^$#@"
)

func requestSign(input string) string {
	method := sha1.New()
	method.Write([]byte(input))
	bs := method.Sum([]byte(Key))
	result := fmt.Sprintf("%x", bs)
	return result
}
