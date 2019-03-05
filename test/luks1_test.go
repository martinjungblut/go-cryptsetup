package test

import (
	"cryptsetup"
	"cryptsetup/devicetypes"
	"testing"
)

func Test_LUKS1_FillDefaultValues_ShouldFillAllFields(test *testing.T) {
	luks1 := devicetypes.LUKS1{}

	luks1.FillDefaultValues()

	if luks1.Hash != "sha256" {
		test.Error("Default Hash should be 'sha256'.")
	}
}

func Test_LUKS1_FillDefaultValues_ShouldFillNoFields(test *testing.T) {
	luks1 := devicetypes.LUKS1{Hash: "sha1"}

	luks1.FillDefaultValues()

	if luks1.Hash != "sha1" {
		test.Error("Default Hash should be 'sha1'.")
	}
}

func Test_LUKS1_Format(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(&devicetypes.LUKS1{}, &cryptsetup.GenericParams{})
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
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	luks1 := &devicetypes.LUKS1{}
	_ = device.Format(luks1, &cryptsetup.GenericParams{})

	err = device.Load(luks1)
	if err != nil {
		test.Error(err)
	}

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}
