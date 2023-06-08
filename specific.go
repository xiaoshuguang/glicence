package glicence

import (
	"fmt"
	"github.com/super-l/machine-code/machine"
)

const (
	defaultKey = "yjtJ6frmuy4t5cqf"
	defaultIV  = "OB0tDW9wvCRLq0Dz"
)

func GetMachineSpecific() (string, error) {
	uid, cpuid, mac := "", "", ""
	var err error
	uid, err = machine.GetPlatformUUID()
	if err != nil {
		return "", err
	}
	cpuid, err = machine.GetCpuId()
	if err != nil {
		return "", err
	}
	mac, err = machine.GetMACAddress()
	if err != nil {
		return "", err
	}
	sysInfo := fmt.Sprintf("%s|%s|%s", uid, cpuid, mac)
	return sysInfo, nil
}

func GetMachineFingerPrint() (string, error) {
	sysInfo, err := GetMachineSpecific()
	if err != nil {
		return "", err
	}
	rCode := GetSHA256HashCode([]byte(sysInfo))
	return rCode, nil
}

func GetLocalKeyAndIV() (string, string) {
	fingerPrint, err := GetMachineFingerPrint()
	if err == nil {
		bIndex := len(fingerPrint) - 16
		return fingerPrint[:16], fingerPrint[bIndex:]
	}
	return defaultKey, defaultIV
}
