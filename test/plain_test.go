package test

import (
	"cryptsetup"
	"cryptsetup/devicetypes"
	"testing"
)

func Test_Plain_DefaultPlain(test *testing.T) {
	plain := devicetypes.DefaultPlain()

	if plain.Hash != "sha256" {
		test.Error("Default Hash should be 'sha256'.")
	}

	if plain.Offset != 0 {
		test.Error("Default Offset should be 0.")
	}

	if plain.Skip != 0 {
		test.Error("Default Skip should be 0.")
	}

	if plain.Size != 0 {
		test.Error("Default Size should be 0.")
	}

	if plain.SectorSize != 0 {
		test.Error("Default SectorSize should be 0.")
	}
}

func Test_Plain_Format(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultPlain(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	if device.Type() != "PLAIN" {
		test.Error("Expected type: PLAIN.")
	}

	err = device.Format(devicetypes.DefaultPlain(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Plain_ActivateByPassphrase_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultPlain(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DevicePath, 0, PassKey, cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DevicePath)
	testWrapper.AssertNoError(err)
}

func Test_Plain_ActivateByVolumeKey_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	genericParams := cryptsetup.GenericParams{
		Cipher: "aes",
		CipherMode: "xts-plain64",
		VolumeKey: generateKey(32, test),
		VolumeKeySize: 32,
	}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultPlain(), &genericParams)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, genericParams.VolumeKey, genericParams.VolumeKeySize, cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "PLAIN" {
		test.Error("Expected type: PLAIN.")
	}
}

func Test_Plain_Load_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	plain := devicetypes.DefaultPlain()
	err = device.Format(plain, cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.Load(plain)
	testWrapper.AssertUnsupportedError(err)
}

func Test_Plain_KeyslotAddByVolumeKey_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultPlain(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "")
	testWrapper.AssertUnsupportedError(err)
}

func Test_Plain_KeyslotAddByPassphrase_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultPlain(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(0, "", "")
	testWrapper.AssertUnsupportedError(err)
}

func Test_Plain_KeyslotChangeByPassphrase_Should_Not_Be_Supported(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultPlain(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotChangeByPassphrase(0, 0, "", "")
	testWrapper.AssertUnsupportedError(err)
}
