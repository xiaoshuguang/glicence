package glicence

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
)

type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Panic(args ...interface{})
}

type PersistConfig struct {
	PermitFile  string `json:"permitFile"`
	ExpiredFile string `json:"expiredFile"`
}

type PermitCheck interface {
	CheckRequestCode(requestCode string) error
	GetRequestCode() (string, error)
}

type Persist interface {
	PermitCheck
	PersistPermit(permit *Permit) error
	LoadPermit() (*Permit, error)
	LoadExpired() (*ExpiredPermits, error)
	GetKeyAndIV() (string, string)
}

func InitLocalPersist(config *PersistConfig, logger Logger) (Persist, error) {
	if logger == nil {
		msg := "nil logger"
		fmt.Println(msg)
		return nil, errors.Errorf(msg)
	}
	if len(config.PermitFile) > 0 && len(config.ExpiredFile) > 0 {
		localPersist := &LocalPersist{
			PermitFilePath:  config.PermitFile,
			ExpiredFilePath: config.ExpiredFile,
			logger:          logger,
		}
		return localPersist, nil
	} else {
		return nil, errors.Errorf("no permit files")
	}
}

type LocalPersist struct {
	PermitFilePath  string
	ExpiredFilePath string
	logger          Logger
}

func (persist *LocalPersist) GetKeyAndIV() (string, string) {
	return GetLocalKeyAndIV()
}

func (persist *LocalPersist) PersistPermit(permit *Permit) error {
	permit.lock.Lock()
	defer permit.lock.Unlock()
	return persist.doPersistPermit(permit)
}

func (persist *LocalPersist) LoadPermit() (*Permit, error) {
	permit := &Permit{}
	permit.Persister = persist
	permitFile := persist.PermitFilePath
	if len(permitFile) > 0 {
		file, err := os.Open(permitFile)
		if err != nil {
			fmt.Printf("open permit file error: %s", err.Error())
			return nil, err
		}
		defer file.Close()
		//读取文件的内容
		info, _ := file.Stat()
		if info.Size() > 0 {
			buf := make([]byte, info.Size())
			file.Read(buf)
			key, iv := persist.GetKeyAndIV()
			err = permit.Decrypt(buf, key, iv)
			if err != nil {
				persist.logger.Errorf("decrypt permit file error: %q", err)
				return nil, err
			}
		}
	}
	return permit, nil
}

func (persist *LocalPersist) LoadExpired() (*ExpiredPermits, error) {
	expired := &ExpiredPermits{}
	expiredFile := persist.ExpiredFilePath
	if len(expiredFile) > 0 {
		file, err := os.Open(expiredFile)
		if err != nil {
			persist.logger.Errorf("open expired file error: %q", err)
			return nil, err
		}
		defer file.Close()
		//读取文件的内容
		info, _ := file.Stat()
		if info.Size() > 0 {
			buf := make([]byte, info.Size())
			file.Read(buf)
			key, iv := persist.GetKeyAndIV()
			err = expired.Decrypt(buf, key, iv)
			if err != nil {
				persist.logger.Errorf("decrypt expired file error: %q", err)
				return nil, err
			}
		}
	}
	return expired, nil
}

func (persist *LocalPersist) doPersistPermit(permit *Permit) error {
	key, iv := persist.GetKeyAndIV()
	bytes, err := permit.doEncrypt(key, iv)
	if err != nil {
		return err
	}
	pFile, err := os.OpenFile(persist.PermitFilePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer pFile.Close()
	_, err = pFile.Write(bytes)
	if err != nil {
		return err
	}
	return persist.PersistExpired(permit.Expired)
}

func (persist *LocalPersist) PersistExpired(expired *ExpiredPermits) error {
	expired.lock.Lock()
	defer expired.lock.Unlock()
	return persist.doPersistExpired(expired)
}

func (persist *LocalPersist) CheckRequestCode(requestCode string) error {
	rCode, err := persist.GetRequestCode()
	if err != nil {
		return err
	}
	if rCode != requestCode {
		return errors.Errorf("not match")
	}
	return nil
}

func (persist *LocalPersist) GetRequestCode() (string, error) {
	return GetMachineFingerPrint()
}

func (persist *LocalPersist) doPersistExpired(expired *ExpiredPermits) error {
	if expired == nil {
		return nil
	}
	key, iv := persist.GetKeyAndIV()
	bytes, err := expired.doEncrypt(key, iv)
	if err != nil {
		return err
	}
	pFile, err := os.OpenFile(persist.ExpiredFilePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer pFile.Close()
	_, err = pFile.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}
