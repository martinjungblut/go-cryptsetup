package cryptsetup

import (
	"testing"
)

func Test_LUKS2_Format(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS2 parameters.")
	}

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_Format_Using_PbkdfType(test *testing.T) {
	testWrapper := TestWrapper{test}

	pbkdftype := PbkdfType{
		Type:            "argon2id",
		Hash:            "sha512",
		TimeMs:          20 * 1000,
		Iterations:      2,
		MaxMemoryKb:     16 * 1024,
		ParallelThreads: 2,
		Flags:           1,
	}
	luks2 := LUKS2{
		SectorSize: 512,
		PBKDFType:  &pbkdftype,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(luks2, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS2 parameters.")
	}

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_Format_Using_IntegrityParams_Should_Fail_For_Invalid_Parameters(test *testing.T) {
	testWrapper := TestWrapper{test}

	integrityParams := IntegrityParams{
		JournalCrypt: "poly1305",
	}
	luks2 := LUKS2{
		SectorSize:      512,
		Integrity:       "poly1305",
		IntegrityParams: &integrityParams,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(luks2, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -95)

	device.Free()
}

func Test_LUKS2_Format_Using_IntegrityParams(test *testing.T) {
	testWrapper := TestWrapper{test}

	integrityParams := IntegrityParams{
		Integrity: "poly1305",
	}
	luks2 := LUKS2{
		SectorSize:      4096,
		IntegrityParams: &integrityParams,
	}
	genericParams := GenericParams{
		Cipher:        "chacha20",
		CipherMode:    "random",
		VolumeKeySize: 64,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(luks2, genericParams)
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS2 parameters.")
	}

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_Load_ActivateByPassphrase_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}
	luks2 := LUKS2{SectorSize: 512}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(luks2, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)
	device.Free()

	device, err = Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Load(nil)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_Load_ActivateByPassphrase_Free_InitByName_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}
	luks2 := LUKS2{SectorSize: 512}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(luks2, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)
	device.Free()

	device, err = Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Load(nil)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	device.Free()

	device, err = InitByName(DeviceName)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_ActivateByVolumeKey_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	genericParams := GenericParams{
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		VolumeKey:     generateKey(512/8, test),
		VolumeKeySize: 512 / 8,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(LUKS2{SectorSize: 512}, genericParams)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, genericParams.VolumeKey, genericParams.VolumeKeySize, CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_ActivateByAutoGeneratedVolumeKey_Deactivate(test *testing.T) {
	testWrapper := TestWrapper{test}

	genericParams := GenericParams{
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		VolumeKeySize: 512 / 8,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(LUKS2{SectorSize: 512}, genericParams)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, "", genericParams.VolumeKeySize, CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	device.Free()
}

func Test_LUKS2_KeyslotAddByVolumeKey(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)

	device.Free()
}

func Test_LUKS2_KeyslotAddByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByPassphrase(1, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -22)

	device.Free()
}

func Test_LUKS2_KeyslotChangeByPassphrase(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	err = device.KeyslotAddByVolumeKey(0, "", "testPassphrase")
	testWrapper.AssertNoError(err)

	err = device.KeyslotChangeByPassphrase(0, 0, "testPassphrase", "secondTestPassphrase")
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "secondTestPassphrase", CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertNoError(err)

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	err = device.ActivateByPassphrase(DeviceName, 0, "testPassphrase", CRYPT_ACTIVATE_READONLY)
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -1)

	device.Free()
}

func Test_LUKS2_Wipe(test *testing.T) {
	testWrapper := TestWrapper{test}

	luks2Params := LUKS2{
		SectorSize: 512,
		Integrity:  "hmac(sha256)",
	}
	genericParams := GenericParams{
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		VolumeKeySize: 512/8 + 256/8,
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)

	hashBeforeFormat := getFileMD5(DevicePath, test)

	err = device.Format(luks2Params, genericParams)
	testWrapper.AssertNoError(err)

	err = device.ActivateByVolumeKey(DeviceName, "", genericParams.VolumeKeySize, (CRYPT_ACTIVATE_PRIVATE | CRYPT_ACTIVATE_NO_JOURNAL))
	testWrapper.AssertNoError(err)

	progressFunc := func(size, offset uint64) int {
		prog := (float64(offset) / float64(size)) * 100
		test.Logf("Wipe in progress: %.2f%%", prog)
		return 0
	}

	err = device.Wipe("/dev/mapper/"+DeviceName, CRYPT_WIPE_ZERO, 0, 0, 1024*1024, 0, progressFunc)
	testWrapper.AssertNoError(err)

	hashAfterFormat := getFileMD5(DevicePath, test)

	if hashBeforeFormat == hashAfterFormat {
		test.Error("Unsuccessful call to Format() when using LUKS2 parameters.")
	}

	if device.Type() != "LUKS2" {
		test.Error("Expected type: LUKS2.")
	}

	err = device.Deactivate(DeviceName)
	testWrapper.AssertNoError(err)

	device.Free()
}
