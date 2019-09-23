package test

import (
	"cryptsetup"
	"testing"
)

func Test_Plain_ActivateByPassphrase_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DevicePath, 0, PassKey, cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DevicePath)
	testWrapper.AssertNoError(err)

	device.Free()
}

func Test_Plain_ActivateByVolumeKey_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	genericParams := cryptsetup.GenericParams{
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		VolumeKey:     generateKey(512/8, test),
		VolumeKeySize: 512 / 8,
	}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, genericParams)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, genericParams.VolumeKey, genericParams.VolumeKeySize, cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "PLAIN" {
		test.Error("Expected type: PLAIN.")
	}

	device.Free()
}

func Test_Plain_Format_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	if device.Type() != "PLAIN" {
		test.Error("Expected type: PLAIN.")
	}

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertErrorCodeEquals(err, -22)

	device.Free()
}

func Test_Plain_KeyslotAddByVolumeKey_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "")
	testWrapper.AssertErrorCodeEquals(err, -22)

	device.Free()
}

func Test_Plain_KeyslotAddByPassphrase_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(0, "", "")
	testWrapper.AssertErrorCodeEquals(err, -22)

	device.Free()
}

func Test_Plain_KeyslotChangeByPassphrase_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(cryptsetup.Plain{Hash: "sha256"}, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotChangeByPassphrase(0, 0, "", "")
	testWrapper.AssertErrorCodeEquals(err, -22)

	device.Free()
}
