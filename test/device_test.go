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

	err = device.Deactivate("testDeviceName")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -19)
}
