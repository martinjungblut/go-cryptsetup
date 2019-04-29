package test

import (
	"cryptsetup"
	"cryptsetup/devicetypes"
	"testing"
)

func Test_LUKS2_DefaultLUKS2(test *testing.T) {
	luks2 := devicetypes.DefaultLUKS2()

	if luks2.SectorSize != 512 {
		test.Error("Default sector size should be '512'.")
	}
}

func Test_LUKS2_Format_Using_DefaultLUKS2(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(devicetypes.DefaultLUKS2(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS2 parameters.")
	}

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}
}

// TODO: add comparison to "default MD5", maybe using the test tables
func Test_LUKS2_Format_Using_PbkdfType(test *testing.T) {
	testWrapper := TestWrapper{test}

	pbkdftype := devicetypes.PbkdfType{
		Type:            "argon2id",
		Hash:            "sha512",
		TimeMs:          20 * 1000,
		Iterations:      2,
		MaxMemoryKb:     16 * 1024,
		ParallelThreads: 2,
		Flags:           1,
	}
	luks2 := devicetypes.LUKS2{
		SectorSize: 512,
		PBKDFType:  &pbkdftype,
	}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(luks2, cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS2 parameters.")
	}

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}
}

func Test_LUKS2_Format_Using_IntegrityParams_Should_Fail_For_Invalid_Parameters(test *testing.T) {
	testWrapper := TestWrapper{test}

	integrityParams := devicetypes.IntegrityParams{
		JournalCrypt: "poly1305",
	}
	luks2 := devicetypes.LUKS2{
		SectorSize:      512,
		Integrity:       "poly1305",
		IntegrityParams: &integrityParams,
	}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(luks2, cryptsetup.DefaultGenericParams())
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -95)
}

func Test_LUKS2_Load_ActivateByPassphrase_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}
	luks2 := devicetypes.DefaultLUKS2()

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(luks2, cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	device, err = cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Load(luks2)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}
}

func Test_LUKS2_ActivateByVolumeKey_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	genericParams := cryptsetup.GenericParams{
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		VolumeKey:     generateKey(32, test),
		VolumeKeySize: 32,
	}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS2(), &genericParams)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, genericParams.VolumeKey, genericParams.VolumeKeySize, cryptsetup.CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}
}

func Test_LUKS2_KeyslotAddByVolumeKey(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS2(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_LUKS2_KeyslotAddByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS2(), cryptsetup.DefaultGenericParams())
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_LUKS2_KeyslotChangeByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := cryptsetup.Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(devicetypes.DefaultLUKS2(), cryptsetup.DefaultGenericParams())
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
