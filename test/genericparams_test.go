package test

import (
	"cryptsetup"
	"testing"
)

func Test_FillDefaultValues_ShouldFillAllFields(test *testing.T) {
	p := cryptsetup.GenericParams{}

	p.FillDefaultValues()

	if p.Cipher != "aes" {
		test.Error("Default Cipher should be 'aes'.")
	}

	if p.CipherMode != "xts-plain64" {
		test.Error("Default CipherMode should be 'xts-plain64'.")
	}

	if p.VolumeKeySize != (256 / 8) {
		test.Error("Default VolumeKeySize should be 256 / 8.")
	}
}

func Test_FillDefaultValues_ShouldFillNoFields(test *testing.T) {
	params := cryptsetup.GenericParams{Cipher: "twofish", CipherMode: "ecb", VolumeKeySize: 16}

	params.FillDefaultValues()

	if params.Cipher != "twofish" {
		test.Error("Default Cipher should be 'twofish'.")
	}

	if params.CipherMode != "ecb" {
		test.Error("Default CipherMode should be 'ecb'.")
	}

	if params.VolumeKeySize != 16 {
		test.Error("Default VolumeKeySize should be 16.")
	}
}
