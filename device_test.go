package cryptsetup

import (
	"encoding/json"
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

func Test_Device_InitByName_Fails_If_Device_Is_Not_Active(test *testing.T) {
	testWrapper := TestWrapper{test}

	_, err := InitByName("nonExistingMappedDevice")
	testWrapper.AssertError(err)
	testWrapper.AssertErrorCodeEquals(err, -19)
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

func Test_Device_GetDeviceName(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	defer device.Free()
	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	devicePath := device.GetDeviceName()
	if devicePath != DevicePath {
		test.Errorf("Returned the wrong device path: got %s, expected %s", devicePath, DevicePath)
	}
}

func Test_Device_GetUUID(test *testing.T) {
	testWrapper := TestWrapper{test}

	device := &Device{}
	uid := device.GetUUID()
	if uid != "" {
		test.Error("UUID should be empty")
	}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	defer device.Free()
	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	uid = device.GetUUID()
	if uid == "" {
		test.Error("Should have generated a UUID")
	}

	newUUID := "12345678-1234-1234-1234-12345678abcd"
	device.Free()
	device, err = Init(DevicePath)
	testWrapper.AssertNoError(err)
	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", UUID: newUUID, VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)
	uid = device.GetUUID()
	if uid != newUUID {
		test.Errorf("Returned a different UUID than was set for the device: got %s, expected %s", uid, newUUID)
	}
}

func Test_Device_DumpJSON(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	defer device.Free()

	// Format the device using aes-xts-plain64
	cipher := "aes"
	cipherMode := "xts-plain64"
	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: cipher, CipherMode: cipherMode, VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	// Dump device info
	jsonInfo, err := device.DumpJSON()
	testWrapper.AssertNoError(err)

	// Check that the cipher and cipher mode are correct
	type segment struct {
		Encryption string `json:"encryption"`
	}
	var info struct {
		Segments map[string]segment `json:"segments"`
	}

	err = json.Unmarshal([]byte(jsonInfo), &info)
	testWrapper.AssertNoError(err)

	if len(info.Segments) != 1 {
		test.Errorf("Expected one segment, got %d", len(info.Segments))
	}
	for _, segment := range info.Segments {
		if segment.Encryption != cipher+"-"+cipherMode {
			test.Errorf("Expected encryption to be %s-%s, got %s", cipher, cipherMode, segment.Encryption)
		}
	}
}

func Test_Device_TokenJSON(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	defer device.Free()

	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	out, err := device.TokenJSONGet(0)
	testWrapper.AssertError(err) // no token set
	if out != "" {
		test.Errorf("Expected empty string, got %s", out)
	}

	type tokenStruct struct {
		Type     string `json:"type"`
		Keyslots []int  `json:"keyslots"`
		Data     string `json:"data"`
	}

	newToken := tokenStruct{
		Type:     "unit-test",
		Keyslots: []int{},
		Data:     "foo",
	}
	token, err := json.Marshal(newToken)
	testWrapper.AssertNoError(err)

	tokenID, err := device.TokenJSONSet(CRYPT_ANY_TOKEN, string(token))
	testWrapper.AssertNoError(err)

	out, err = device.TokenJSONGet(tokenID)
	testWrapper.AssertNoError(err)

	var tokenOut tokenStruct
	err = json.Unmarshal([]byte(out), &tokenOut)
	testWrapper.AssertNoError(err)

	if tokenOut.Type != newToken.Type {
		test.Errorf("Expected token type to be %s, got %s", newToken.Type, tokenOut.Type)
	}
	if len(tokenOut.Keyslots) != len(newToken.Keyslots) {
		test.Errorf("Expected token keyslots to be %d, got %d", len(newToken.Keyslots), len(tokenOut.Keyslots))
	}
	if tokenOut.Data != newToken.Data {
		test.Errorf("Expected token data to be %s, got %s", newToken.Data, tokenOut.Data)
	}
}

func Test_Device_TokenAssignKeyslot(test *testing.T) {
	testWrapper := TestWrapper{test}

	device, err := Init(DevicePath)
	testWrapper.AssertNoError(err)
	defer device.Free()

	err = device.Format(LUKS2{SectorSize: 512}, GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	testWrapper.AssertNoError(err)

	keyslot := 0
	tokenID := 0
	err = device.KeyslotAddByVolumeKey(keyslot, "", "firstPassphrase")
	testWrapper.AssertNoError(err)

	err = device.TokenIsAssigned(tokenID, keyslot)
	testWrapper.AssertError(err) // No tokens defined yet

	// No tokens defined yet
	err = device.TokenAssignKeyslot(tokenID, CRYPT_ANY_SLOT)
	testWrapper.AssertError(err)

	// Set a token
	_, err = device.TokenJSONSet(CRYPT_ANY_TOKEN, `{"type":"test","keyslots":[],"data":"foo"}`)
	testWrapper.AssertNoError(err)

	// Assign the token to keyslot
	err = device.TokenAssignKeyslot(CRYPT_ANY_TOKEN, CRYPT_ANY_SLOT)
	testWrapper.AssertNoError(err)

	err = device.TokenIsAssigned(tokenID, keyslot)
	testWrapper.AssertNoError(err)

	// Remove token assignment
	err = device.TokenUnassignKeyslot(CRYPT_ANY_TOKEN, CRYPT_ANY_SLOT)
	testWrapper.AssertNoError(err)

	err = device.TokenIsAssigned(tokenID, keyslot)
	testWrapper.AssertError(err)
}
