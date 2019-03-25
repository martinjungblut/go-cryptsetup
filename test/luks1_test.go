package test

import (
	"cryptsetup"
	"cryptsetup/devicetypes"
	"testing"
)

func Test_LUKS1_DefaultLUKS1(test *testing.T) {
	luks1 := devicetypes.DefaultLUKS1()

	if luks1.Hash != "sha256" {
		test.Error("Default Hash should be 'sha256'.")
	}
}

func Test_LUKS1_Format(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS1 parameters.")
	}

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}

func Test_LUKS1_Load_ActivateByPassphrase_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}
	luks1 := devicetypes.DefaultLUKS1()

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(luks1, cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	device, err = cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Load(luks1)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}

func Test_LUKS1_KeyslotAddByVolumeKey(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_LUKS1_KeyslotAddByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_LUKS1_KeyslotChangeByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotChangeByPassphrase(0, 0, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "secondTestPassphrase", cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -1)
}
