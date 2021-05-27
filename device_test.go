package cryptsetup

import (
	"testing"
)

func Test_Device_Init_Works_If_Device_Is_Found(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	if device.Type() != "" {
		test.Error("Device should have no type.")
	}
}

func Test_Device_Init_Fails_If_Device_Is_Not_Found(test *testing.T) {
	testWrapper := TestWrapper{test}

	_, err := Init("nonExistingDevicePath")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -15)
}

func Test_Device_Free_Works(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(
		LUKS1{Hash: "sha256"},
		GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8},
	)
	testWrapper.AssertNoError(err)

	code := device.Dump()
	if code != 0 {
		test.Error("Dump() should have returned `0`.")
	}

	if device.Free() != true {
		test.Error("Free should have returned `true`.")
	}

	code = device.Dump()
	if code != -22 {
		test.Error("Dump() should have returned `-22`.")
	}
}

func Test_Device_Free_Doesnt_Fail_For_Empty_Device(test *testing.T) {
	device := &Device{}

	if device.Free() != true {
		test.Error("Free should have returned `true`.")
	}

	if device.Free() != false {
		test.Error("Free should have returned `false`.")
	}
}

func Test_Device_Free_Doesnt_Fail_If_Called_Multiple_Times(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(
		LUKS1{Hash: "sha256"},
		GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8},
	)
	testWrapper.AssertNoError(err)

	if device.Free() != true {
		test.Error("Free should have returned `true`.")
	}

	if device.Free() != false {
		test.Error("Free should have returned `false`.")
	}
}

func Test_Device_Deactivate_Fails_If_Device_Is_Not_Active(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -19)
}

func Test_Device_ActivateByPassphrase_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_ActivateByVolumeKey_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	genericParams := GenericParams{
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		VolumeKey:     generateKey(32, test),
		VolumeKeySize: 32,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, genericParams.VolumeKey, genericParams.VolumeKeySize, CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_KeyslotAddByVolumeKey_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_KeyslotAddByPassphrase_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(0, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_KeyslotChangeByPassphrase_Fails_If_Device_Has_No_Type(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.KeyslotChangeByPassphrase(0, 0, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)
}

func Test_Device_VolumeKeyGet(test *testing.T) {
	volumeKeySize := 512 / 8
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: volumeKeySize})
	testWrapper.AssertNoError(err)

	defer device.Free()

	err = device.KeyslotAddByVolumeKey(0, "", "firstPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "firstPassphrase", "secondPassphrase")
	testWrapper.AssertNoError(err)

	volumeKey, volumeKeySlot, err := device.VolumeKeyGet(CRYPT_ANY_SLOT, "secondPassphrase")
	testWrapper.AssertNoError(err)

	if len(volumeKey) != volumeKeySize {
		test.Errorf("Invalid volume key size length: %d", len(volumeKey))
	} else if volumeKeySlot != 1 {
		test.Errorf("Volume key slot should have been 1, but was: %d", volumeKeySlot)
	}
}

func Test_Device_VolumeKeyGet_Fails_If_Wrong_Passphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	defer device.Free()

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	volumeKey, volumeKeySlot, err := device.VolumeKeyGet(CRYPT_ANY_SLOT, "secondTestPassphrase")
	testWrapper.AssertError(err)

	if len(volumeKey) != 0 {
		test.Errorf("Invalid volume key size length: %d", len(volumeKey))
	} else if volumeKeySlot != 0 {
		test.Errorf("Volume key slot should have been zero, but was: %d", volumeKeySlot)
	}
}
