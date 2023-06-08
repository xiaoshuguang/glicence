package glicence

import (
	"encoding/json"
	"github.com/pkg/errors"
	"sync"
	"time"
)

type Permit struct {
	lock          sync.Mutex
	LicenceType   string        `json:"licence_type"`
	Version       string        `json:"version"`
	RequestCode   string        `json:"request_code"`
	RemainingTime time.Duration `json:"remaining_time"`
	RefreshTime   time.Time     `json:"refresh_time"`
	ExpireTime    time.Time     `json:"expire_time"`
	MaxCount      uint          `json:"max_count"`
	Overload      bool          `json:"-"`
	ServerCount   uint          `json:"-"`
	Persister     Persist       `json:"-"`
	Expired       *ExpiredPermits
}

type ExpiredPermits struct {
	lock       sync.Mutex
	ExpiredIDs []string `json:"expired_ids"`
}

func (permit *Permit) GetExpireInfo() (*time.Time, int) {
	permit.lock.Lock()
	defer permit.lock.Unlock()
	if permit.RemainingTime > 0 {
		days := permit.RemainingTime / (time.Hour * 24)
		expireAt := permit.ExpireTime
		return &expireAt, int(days)
	} else {
		return nil, 0
	}
}

func (permit *Permit) IsPermitted() bool {
	if permit.Persister == nil {
		return false
	}
	err := permit.Persister.CheckRequestCode(permit.RequestCode)
	if err != nil {
		return false
	}
	tNow := time.Now()
	return permit.ExpireTime.After(tNow) && permit.RemainingTime > 0
}

func (permit *Permit) CheckAndUpdate() error {
	permit.lock.Lock()
	defer permit.lock.Unlock()
	return permit.doCheckAndUpdate()
}

func (permit *Permit) doCheckAndUpdate() error {
	var err error
	if permit.Persister == nil {
		return errors.Errorf("no permit check")
	}
	err = permit.Persister.CheckRequestCode(permit.RequestCode)
	if err != nil {
		return err
	}
	tNow := time.Now()
	if permit.ExpireTime.After(tNow) {
		if tNow.After(permit.RefreshTime) {
			used := tNow.Sub(permit.RefreshTime)
			permit.RemainingTime = permit.RemainingTime - used
			if permit.RemainingTime > 0 {
				permit.ExpireTime = tNow.Add(permit.RemainingTime)
			} else {
				permit.RemainingTime = 0
				permit.ExpireTime = tNow
				err = errors.Errorf("exceed time limit")
				return err
			}
		}
	} else {
		permit.RemainingTime = 0
		err = errors.Errorf("exceed time limit")
		return err
	}
	permit.RefreshTime = tNow
	if permit.Persister != nil {
		return permit.Persister.PersistPermit(permit)
	} else {
		err = errors.Errorf("no permit persist")
		return err
	}
}

func (permit *Permit) Activate(publicKey []byte, key string) error {
	permit.lock.Lock()
	defer permit.lock.Unlock()
	return permit.doActivate(publicKey, key)
}

func (permit *Permit) doActivate(publicKey []byte, key string) error {
	var err error
	newLicence := &Licence{}
	err = newLicence.ParseActiveCode(publicKey, key)
	if err != nil {
		return err
	}
	if permit.Persister == nil {
		return errors.Errorf("no permit check")
	}
	err = permit.Persister.CheckRequestCode(newLicence.RequestCode)
	if err != nil {
		return err
	}
	if permit.Expired.ExpiredIDs != nil {
		for _, expiredID := range permit.Expired.ExpiredIDs {
			if expiredID == newLicence.Uid {
				return errors.Errorf("active code is expired")
			}
		}
	}
	tNow := time.Now()
	err = permit.Persister.CheckRequestCode(permit.RequestCode)
	if err == nil {
		if permit.ExpireTime.After(tNow) {
			if tNow.After(permit.RefreshTime) {
				used := tNow.Sub(permit.RefreshTime)
				permit.RemainingTime = permit.RemainingTime - used
				if permit.RemainingTime <= 0 {
					permit.RemainingTime = 0
				}
			}
		} else {
			permit.RemainingTime = 0
		}
	} else {
		permit.RemainingTime = 0
	}
	permit.LicenceType = newLicence.LicenceType
	permit.Version = newLicence.Version
	permit.RequestCode = newLicence.RequestCode
	permit.RemainingTime = permit.RemainingTime + newLicence.ValidityTime
	permit.RefreshTime = tNow
	permit.ExpireTime = tNow.Add(permit.RemainingTime)
	if newLicence.MaxCount > permit.MaxCount {
		permit.MaxCount = newLicence.MaxCount
	}
	permit.Expired.ExpiredIDs = append(permit.Expired.ExpiredIDs, newLicence.Uid)
	return nil
}

func (permit *Permit) Encrypt(key, iv string) ([]byte, error) {
	permit.lock.Lock()
	defer permit.lock.Unlock()
	return permit.doEncrypt(key, iv)
}

func (permit *Permit) doEncrypt(key, iv string) ([]byte, error) {
	bytes, err := json.Marshal(permit)
	if err != nil {
		return nil, err
	}
	cipher := AESCBCCipher{
		Key: key,
		IV:  iv,
	}
	encrypted, err := cipher.EncryptBytes(bytes)
	if err != nil {
		return nil, err
	}
	return []byte(encrypted), nil
}

func (permit *Permit) Decrypt(encrypted []byte, key, iv string) error {
	permit.lock.Lock()
	defer permit.lock.Unlock()
	return permit.doDecrypt(encrypted, key, iv)
}

func (permit *Permit) doDecrypt(encrypted []byte, key, iv string) error {
	cipher := AESCBCCipher{
		Key: key,
		IV:  iv,
	}
	decrypted, err := cipher.DecryptBytes(encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(decrypted), permit)
}

func (used *ExpiredPermits) Encrypt(key, iv string) ([]byte, error) {
	used.lock.Lock()
	defer used.lock.Unlock()
	return used.doEncrypt(key, iv)
}

func (used *ExpiredPermits) doEncrypt(key, iv string) ([]byte, error) {
	bytes, err := json.Marshal(used)
	if err != nil {
		return nil, err
	}
	cipher := AESCBCCipher{
		Key: key,
		IV:  iv,
	}
	encrypted, err := cipher.EncryptBytes(bytes)
	if err != nil {
		return nil, err
	}
	return []byte(encrypted), nil
}

func (used *ExpiredPermits) Decrypt(encrypted []byte, key, iv string) error {
	used.lock.Lock()
	defer used.lock.Unlock()
	return used.doDecrypt(encrypted, key, iv)
}

func (used *ExpiredPermits) doDecrypt(encrypted []byte, key, iv string) error {
	cipher := AESCBCCipher{
		Key: key,
		IV:  iv,
	}
	decrypted, err := cipher.DecryptBytes(encrypted)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(decrypted), used)
}
