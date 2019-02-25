package test

import (
	"cryptsetup"
	"testing"
)

func Test_LUKS1Params_FillDefaultValues_ShouldFillAllFields(test *testing.T) {
	luksParams := cryptsetup.LUKS1Params{}

	luksParams.FillDefaultValues()

	if luksParams.Hash != "sha256" {
		test.Error("Default Hash should be 'sha256'.")
	}
}

func Test_LUKS1Params_FillDefaultValues_ShouldFillNoFields(test *testing.T) {
	luksParams := cryptsetup.LUKS1Params{Hash: "sha1"}

	luksParams.FillDefaultValues()

	if luksParams.Hash != "sha1" {
		test.Error("Default Hash should be 'sha1'.")
	}
}

func Test_LUKS1_Format(test *testing.T) {
	device, err := cryptsetup.Init(DevicePath)
	if err != nil {
		test.Error(err)
	}

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(&cryptsetup.LUKS1Params{}, &cryptsetup.GenericParams{})
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

	luksParams := &cryptsetup.LUKS1Params{}
	_ = device.Format(luksParams, &cryptsetup.GenericParams{})

	err = device.Load(luksParams)
	if err != nil {
		test.Error(err)
	}

	if device.Type() != "LUKS1" {
		test.Error("Expected type: LUKS1.")
	}
}
