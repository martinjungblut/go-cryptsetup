package test

import (
	"cryptsetup"
	"cryptsetup/devicetypes"
	"fmt"
	"testing"
)

func Test_Device_Init_WorksIfDeviceIsFound(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)

	if err != nil {
		test.Error(err)
	}

	if device.Type() != "" {
		test.Error("Device should have no type.")
	}
}

func Test_Device_Init_FailsIfDeviceIsNotFound(test *testing.T) {
	_, err := cryptsetup.Init("nonExistingDevicePath")

	if err == nil {
		test.Error("Init() did not return an error, when it should have.")
	}
	code := err.(*cryptsetup.Error).Code()
	if code != -15 {
		test.Error(fmt.Sprintf("Init() should have failed with error code '-15', but code was returned '%d' instead.", code))
	}
}

func Test_Device_AddPassphraseByVolumeKey(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	_ = device.Format(&devicetypes.LUKS1Params{}, &cryptsetup.GenericParams{})

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	if err != nil {
		test.Error(err)
	}

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	if err == nil {
		test.Error("AddPassphraseByVolumeKey() should have failed with error code '-22', but no error was returned.")
	}
	code := err.(*cryptsetup.Error).Code()
	if code != -22 {
		test.Error(fmt.Sprintf("AddPassphraseByVolumeKey() should have failed with error code '-22', but code was returned '%d' instead.", code))
	}
}

func Test_Device_AddPassphraseByPassphrase(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	_ = device.Format(&devicetypes.LUKS1Params{}, &cryptsetup.GenericParams{})

	err = device.AddPassphraseByVolumeKey(0, "", "testPassphrase")
	if err != nil {
		test.Error(err)
	}

	err = device.AddPassphraseByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	if err != nil {
		test.Error(err)
	}

	err = device.AddPassphraseByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	if err == nil {
		test.Error("AddPassphraseByPassphrase() should have failed with error code '-22', but no error was returned.")
	}
	code := err.(*cryptsetup.Error).Code()
	if code != -22 {
		test.Error(fmt.Sprintf("AddPassphraseByPassphrase() should have failed with error code '-22', but code was returned '%d' instead.", code))
	}
}

func Test_Device_ActivateByPassphrase(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	err = device.Format(&devicetypes.LUKS1Params{}, &cryptsetup.GenericParams{})
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

func Test_Device_Deactivate(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	err = device.Deactivate("testDeviceName")
	if err == nil {
		test.Error("Deactivate() should have failed with error code '-19', but no error was returned.")
	}
	code := err.(*cryptsetup.Error).Code()
	if code != -19 {
		test.Error(fmt.Sprintf("Deactivate() should have failed with error code '-19', but code was returned '%d' instead.", code))
	}
}
