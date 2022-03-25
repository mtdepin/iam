package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

const (
	salt = "mtyw-oss-password-12345678901234"
)

//func aesEncrypt(passwd string) (key ObjectKey) {
//	data := []byte(salt)
//
//	key = GenerateKey(data,nil)
//	s := key.Seal(data,GenerateIV(rand.Reader), S3.String(), bucket, passwd)
//	//IAAfAJdrqlaeklKZRkMiIn1P8HP7+49aSTqlfM6ZbnQ/mHvQ3nlDQN6F1raABZyHnYyCRcjwb1g/rTcvSu58qw==
//	sr := base64.StdEncoding.EncodeToString(s.Key[:])
//	fmt.Println(sr)
//	return
//}
//func aesDecrypt()  {
//	data := []byte(salt)
//
//	key := GenerateKey(data,nil)
//	sealedKey := SealedKey{
//		IV:        GenerateIV(rand.Reader),
//		Algorithm: SealAlgorithm,
//	}
//	s := key.Unseal(data,sealedKey, S3.String(), bucket, passwd)
//	//IAAfAJdrqlaeklKZRkMiIn1P8HP7+49aSTqlfM6ZbnQ/mHvQ3nlDQN6F1raABZyHnYyCRcjwb1g/rTcvSu58qw==
//	sr := base64.StdEncoding.EncodeToString(s.Key[:])
//	fmt.Println(sr)
//	return
//}

func PasswordEncrypt(password string) string {
	// 不对空字符串加密
	//if password == "" {
	//	return password
	//}
	//xpass, err := aesEncrypt([]byte(password), []byte(salt))
	//if err != nil {
	//	logger.Error("密码加密失败", err)
	//	return ""
	//}
	//pass64 := base64.StdEncoding.EncodeToString(xpass)
	//return pass64
	return password
}

func PasswordDecrypt(password string) string {
	// 不对空字符串解密
	//if password == "" {
	//	return password
	//}
	//bytesPass, err := base64.StdEncoding.DecodeString(password)
	//if err != nil {
	//	logger.Error("密码解密失败", err)
	//	return ""
	//}
	//
	//t, err := aesDecrypt(bytesPass, []byte(salt))
	//if err != nil {
	//	logger.Error("密码解密失败", err)
	//	return ""
	//}
	//return fmt.Sprintf("%s", t)
	return password
}

//@brief:填充明文
func pKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//@brief:去除填充数据
func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//@brief:AES加密
func aesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	origData = pKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//@brief:AES解密
func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pKCS5UnPadding(origData)
	return origData, nil
}
