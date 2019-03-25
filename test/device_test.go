package test

import (
	"cryptsetup"
	"testing"
)

func Test_Device_Init_Works_If_Device_Is_Found(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	if device.Type() != "" {
		test.Error("Device should have no type.")
	}
}

func Test_Device_Init_Fails_If_Device_Is_Not_Found(test *testing.T) {
	testWrapper := TestWrapper{test}

	_, err := cryptsetup.Init("nonExistingDevicePath")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -15)
}

func Test_Device_Deactivate_Fails_If_Device_Is_Not_Active(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -19)
}

func Test_Device_ActivateByPassphrase_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_KeyslotAddByVolumeKey_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_KeyslotAddByPassphrase_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(0, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}
