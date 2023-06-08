package glicence

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/pkg/errors"
)
import "crypto/cipher"
import "bytes"
import "encoding/base64"

type AESCBCCipher struct {
	Key string
	IV  string
}

func (aesCipher *AESCBCCipher) Encrypt(text []byte) (encrypted string, rError error) {
	defer func() {
		if err := recover(); err != nil {
			rError = errors.Errorf("encrypt error: %s", err)
		}
	}()
	//生成cipher.Block 数据块
	key := []byte(aesCipher.Key)
	iv := []byte(aesCipher.IV)
	block, err := aes.NewCipher(key)
	if err != nil {
		rError = err
		return encrypted, rError
	}
	//填充内容，如果不足16位字符
	blockSize := block.BlockSize()
	originData := pad(text, blockSize)
	//加密方式
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//加密，输出到[]byte数组
	encryptedData := make([]byte, len(originData))
	blockMode.CryptBlocks(encryptedData, originData)
	encrypted = base64.StdEncoding.EncodeToString(encryptedData)
	return encrypted, rError
}

func (aesCipher *AESCBCCipher) EncryptBytes(text []byte) (encrypted []byte, rError error) {
	defer func() {
		if err := recover(); err != nil {
			rError = errors.Errorf("encrypt error: %s", err)
		}
	}()
	//生成cipher.Block 数据块
	key := []byte(aesCipher.Key)
	iv := []byte(aesCipher.IV)
	block, err := aes.NewCipher(key)
	if err != nil {
		rError = err
		return encrypted, rError
	}
	//填充内容，如果不足16位字符
	blockSize := block.BlockSize()
	originData := pad(text, blockSize)
	//加密方式
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//加密，输出到[]byte数组
	encrypted = make([]byte, len(originData))
	blockMode.CryptBlocks(encrypted, originData)
	return encrypted, rError
}

func pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func (aesCipher *AESCBCCipher) Decrypt(text string) (decrypted string, rError error) {
	defer func() {
		if err := recover(); err != nil {
			rError = errors.Errorf("encrypt error: %s", err)
		}
	}()
	decodeData, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		rError = err
		return decrypted, rError
	}
	key := []byte(aesCipher.Key)
	iv := []byte(aesCipher.IV)
	//生成密码数据块cipher.Block
	block, _ := aes.NewCipher(key)
	//解密模式
	blockMode := cipher.NewCBCDecrypter(block, iv)
	//输出到[]byte数组
	originData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(originData, decodeData)
	//去除填充,并返回
	decrypted = string(unPad(originData))
	return decrypted, rError
}

func (aesCipher *AESCBCCipher) DecryptBytes(text []byte) (decrypted []byte, rError error) {
	defer func() {
		if err := recover(); err != nil {
			rError = errors.Errorf("encrypt error: %s", err)
		}
	}()
	key := []byte(aesCipher.Key)
	iv := []byte(aesCipher.IV)
	//生成密码数据块cipher.Block
	block, _ := aes.NewCipher(key)
	//解密模式
	blockMode := cipher.NewCBCDecrypter(block, iv)
	//输出到[]byte数组
	originData := make([]byte, len(text))
	blockMode.CryptBlocks(originData, text)
	//去除填充,并返回
	decrypted = unPad(originData)
	return decrypted, rError
}

func unPad(ciphertext []byte) []byte {
	length := len(ciphertext)
	//去掉最后一次的padding
	unPadding := int(ciphertext[length-1])
	return ciphertext[:(length - unPadding)]
}

func GetSHA256HashCode(message []byte) string {
	//创建一个基于SHA256算法的hash.Hash接口的对象
	hash := sha256.New()
	//输入数据
	hash.Write(message)
	//计算哈希值
	hashBytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	hashCode := hex.EncodeToString(hashBytes)
	//返回哈希值
	return hashCode
}
