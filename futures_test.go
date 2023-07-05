//go:build cryptsetup2.4

package cryptsetup

import (
	"encoding/json"
	"testing"
)

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
