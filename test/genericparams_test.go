package test

import (
	"cryptsetup"
	"testing"
)

func Test_GenericParams_DefaultGenericParams(test *testing.T) {
	params := cryptsetup.DefaultGenericParams()

	if params.Cipher != "aes" {
		test.Error("Default Cipher should be 'aes'.")
	}

	if params.CipherMode != "xts-plain64" {
		test.Error("Default CipherMode should be 'xts-plain64'.")
	}

	if params.VolumeKeySize != (256 / 8) {
		test.Error("Default VolumeKeySize should be 256 / 8.")
	}
}
