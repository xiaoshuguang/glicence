package glicence

import (
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/wenzhenxi/gorsa"
	"time"
)

type Licence struct {
	LicenceType  string        `json:"licence_type"`
	Version      string        `json:"version"`
	ValidityTime time.Duration `json:"validity_days"`
	RequestCode  string        `json:"request_code"`
	Uid          string        `json:"uid"`
	MaxCount     uint          `json:"max_count"`
}

func (licence *Licence) ToBytes() ([]byte, error) {
	return json.Marshal(licence)
}

func (licence *Licence) FromBytes(bytes []byte) error {
	return json.Unmarshal(bytes, licence)
}

func (licence *Licence) PrivateCrypt(privateKey []byte) ([]byte, error) {
	bytes, err := licence.ToBytes()
	if err != nil {
		return nil, err
	}
	if err = gorsa.RSA.SetPrivateKey(string(privateKey)); err != nil {
		return nil, err
	}
	return gorsa.RSA.PriKeyENCTYPT(bytes)
}

func (licence *Licence) PublicDeCrypt(publicKey []byte, crypted []byte) error {
	if err := gorsa.RSA.SetPublicKey(string(publicKey)); err != nil {
		return err
	}
	deCrypted, err := gorsa.RSA.PubKeyDECRYPT(crypted)
	if err != nil {
		return err
	}
	return licence.FromBytes(deCrypted)
}

func (licence *Licence) GetActiveCode(privateKey []byte) (string, error) {
	crypted, err := licence.PrivateCrypt(privateKey)
	if err != nil {
		return "", err
	}
	baseCode := base64.StdEncoding.EncodeToString(crypted)
	return baseCode, nil
}

func (licence *Licence) ParseActiveCode(publicKey []byte, key string) error {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}
	return licence.PublicDeCrypt(publicKey, decoded)
}

func GenerateActiveCode(privateKey []byte, requestCode, licenceType, version string, days uint, maxServers uint) (string, error) {
	uid, _ := uuid.NewUUID()
	licence := &Licence{
		LicenceType:  licenceType,
		Version:      version,
		ValidityTime: time.Hour * 24 * time.Duration(days),
		RequestCode:  requestCode,
		Uid:          uid.String(),
		MaxCount:     maxServers,
	}
	crypted, err := licence.PrivateCrypt(privateKey)
	if err != nil {
		return "", err
	}
	baseCode := base64.StdEncoding.EncodeToString(crypted)
	return baseCode, nil
}
