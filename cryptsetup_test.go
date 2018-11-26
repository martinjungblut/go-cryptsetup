package cryptsetup

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
)

const PassKey string = "testPassKey"
const DevicePath string = "testDevice"

func getFileMD5(filePath string, test *testing.T) string {
	fileHandle, error := os.Open(filePath)
	if error != nil {
		test.Error(error)
	}
	defer fileHandle.Close()

	hash := md5.New()
	_, error = io.Copy(hash, fileHandle)
	if error != nil {
		test.Error(error)
	}

	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func setup() {
	exec.Command("/bin/dd", "if=/dev/zero", fmt.Sprintf("of=%s", DevicePath), "bs=4M", "count=1").Run()
}

func teardown() {
	exec.Command("/bin/rm", "-f", DevicePath).Run()
}

func TestMain(m *testing.M) {
	setup()
	result := m.Run()
	teardown()
	os.Exit(result)
}

func Test_GenericParams_FillDefaultValues_ShouldFillAllFields(test *testing.T) {
	p := GenericParams{}

	p.FillDefaultValues()

	if p.Cipher != "aes" {
		test.Error("Default Cipher should be 'aes'.")
	}

	if p.CipherMode != "xts-plain64" {
		test.Error("Default CipherMode should be 'xts-plain64'.")
	}

	if p.VolumeKeySize != (256 / 8) {
		test.Error("Default VolumeKeySize should be 256 / 8.")
	}
}

func Test_GenericParams_FillDefaultValues_ShouldFillNoFields(test *testing.T) {
	params := GenericParams{Cipher: "twofish", CipherMode: "ecb", VolumeKeySize: 16}

	params.FillDefaultValues()

	if params.Cipher != "twofish" {
		test.Error("Default Cipher should be 'twofish'.")
	}

	if params.CipherMode != "ecb" {
		test.Error("Default CipherMode should be 'ecb'.")
	}

	if params.VolumeKeySize != 16 {
		test.Error("Default VolumeKeySize should be 16.")
	}
}

func Test_LUKS1Params_FillDefaultValues_ShouldFillAllFields(test *testing.T) {
	luksParams := LUKS1Params{}

	luksParams.FillDefaultValues()

	if luksParams.Hash != "sha256" {
		test.Error("Default Hash should be 'sha256'.")
	}
}

func Test_LUKS1Params_FillDefaultValues_ShouldFillNoFields(test *testing.T) {
	luksParams := LUKS1Params{Hash: "sha1"}

	luksParams.FillDefaultValues()

	if luksParams.Hash != "sha1" {
		test.Error("Default Hash should be 'sha1'.")
	}
}

func Test_Init_WorksIfDeviceIsFound(test *testing.T) {
	device, err := Init(DevicePath)

	if err != nil {
		test.Error(err)
	}

	if device.cPointer() == nil {
		test.Error("cPointer() should not be nil.")
	}

	if device.Type() != "" {
		test.Error("Device should have no type.")
	}
}

func Test_Init_FailsIfDeviceIsNotFound(test *testing.T) {
	_, err := Init("nonExistingDevicePath")

	if err == nil {
		test.Error("Init() did not raise an error, when it should have.")
	}
}

func Test_LUKS1_Format(test *testing.T) {
	device, err := Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(&LUKS1Params{}, &GenericParams{})
	if err != nil {
		test.Error(err)
	}

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS1 parameters.")
	}

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}

func Test_LUKS1_Load(test *testing.T) {
	device, err := Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	luksParams := &LUKS1Params{}
	_ = device.Format(luksParams, &GenericParams{})

	err = device.Load(luksParams)
	if err != nil {
		test.Error(err)
	}

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}
