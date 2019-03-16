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
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
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

func Test_LUKS1_ActivateByPassphrase_Deactivate(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	if err != nil {
		test.Error(err)
	}

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	if err != nil {
		test.Error(err)
	}

	err = device.ActivateByPassphrase("testDeviceName", 0, "testPassphrase", cryptsetup.CRYPT_ACTIVATE_READONLY)
	if err != nil {
		test.Error(err)
	}

	err = device.Deactivate("testDeviceName")
	if err != nil {
		test.Error(err)
	}
}

func Test_LUKS1_Load(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	luks1 := devicetypes.DefaultLUKS1()
	err = device.Format(luks1, cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.Load(luks1)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}

func Test_LUKS1_AddPassphraseByVolumeKey(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_LUKS1_AddPassphraseByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS1(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.AddPassphraseByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertNoError(err)

	err = device.AddPassphraseByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}
