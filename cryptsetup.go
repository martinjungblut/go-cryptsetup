package cryptsetup

/*
#cgo CFLAGS: -O2
#cgo LDFLAGS: -lcryptsetup
#include <libcryptsetup.h>
#include <stdlib.h>
#include <stdio.h>
*/
import "C"

import (
	"unsafe"
)

const (
	CRYPT_ANY_SLOT                        = C.CRYPT_ANY_SLOT
	CRYPT_ACTIVATE_READONLY               = C.CRYPT_ACTIVATE_READONLY
	CRYPT_ACTIVATE_NO_UUID                = C.CRYPT_ACTIVATE_NO_UUID
	CRYPT_ACTIVATE_SHARED                 = C.CRYPT_ACTIVATE_SHARED
	CRYPT_ACTIVATE_ALLOW_DISCARDS         = C.CRYPT_ACTIVATE_ALLOW_DISCARDS
	CRYPT_ACTIVATE_PRIVATE                = C.CRYPT_ACTIVATE_PRIVATE
	CRYPT_ACTIVATE_CORRUPTED              = C.CRYPT_ACTIVATE_CORRUPTED
	CRYPT_ACTIVATE_SAME_CPU_CRYPT         = C.CRYPT_ACTIVATE_SAME_CPU_CRYPT
	CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS = C.CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS
	CRYPT_ACTIVATE_IGNORE_CORRUPTION      = C.CRYPT_ACTIVATE_IGNORE_CORRUPTION
	CRYPT_ACTIVATE_RESTART_ON_CORRUPTION  = C.CRYPT_ACTIVATE_RESTART_ON_CORRUPTION
	CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS     = C.CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS
)

// Init initializes a crypt device backed by 'devicePath'.
// Returns a pointer to the newly allocated Device and any error encountered.
// C equivalent: crypt_init
func Init(devicePath string) (*Device, error) {
	cDevicePath := C.CString(devicePath)
	defer C.free(unsafe.Pointer(cDevicePath))

	var cDevice *C.struct_crypt_device

	err := int(C.crypt_init(&cDevice, cDevicePath))
	if err < 0 {
		return nil, &Error{functionName: "crypt_init", code: err}
	}

	return &Device{device: cDevice}, nil
}

// FormatLUKS formats a Device using an LUKS1 partition, but does not activate it.
// C equivalent: crypt_format
func (device *Device) FormatLUKS(cipher string, cipherMode string, uuid string, volumeKey string, volumeKeySize int, params LUKSParams) error {
	cStrType := C.CString(C.CRYPT_LUKS1)
	defer C.free(unsafe.Pointer(cStrType))

	cStrCipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(cStrCipher))

	cStrCipherMode := C.CString(cipherMode)
	defer C.free(unsafe.Pointer(cStrCipherMode))

	var cStrUUID *C.char
	if uuid == "" {
		cStrUUID = nil
	} else {
		cStrUUID = C.CString(uuid)
		defer C.free(unsafe.Pointer(cStrUUID))
	}

	var cStrVolumeKey *C.char
	if volumeKey == "" {
		cStrVolumeKey = nil
	} else {
		cStrVolumeKey = C.CString(volumeKey)
		defer C.free(unsafe.Pointer(cStrVolumeKey))
	}

	var cParams C.struct_crypt_params_luks1
	cParams.data_alignment = C.size_t(params.DataAlignment)
	cParams.hash = C.CString(params.Hash)
	if params.DataDevice != "" {
		cParams.data_device = C.CString(params.DataDevice)
	} else {
		cParams.data_device = nil
	}

	err := C.crypt_format(device.device, cStrType, cStrCipher, cStrCipherMode, cStrUUID, cStrVolumeKey, C.size_t(volumeKeySize), unsafe.Pointer(&cParams))
	if err < 0 {
		return &Error{functionName: "crypt_format", code: int(err)}
	}

	return nil
}

func (device *Device) AddPassphraseToKeyslot(keyslot int, volume_key string, passphrase string) error {
	var cstr_volume_key *C.char
	if volume_key == "" {
		cstr_volume_key = nil
	} else {
		cstr_volume_key = C.CString(volume_key)
		defer C.free(unsafe.Pointer(cstr_volume_key))
	}

	cstr_passphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cstr_passphrase))

	err := C.crypt_keyslot_add_by_volume_key(device.device, C.int(keyslot), cstr_volume_key, C.size_t(len(volume_key)), cstr_passphrase, C.size_t(len(passphrase)))
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_volume_key", code: int(err)}
	}

	return nil
}

func (device *Device) Load() error {
	cstr_type := C.CString(C.CRYPT_LUKS1)
	defer C.free(unsafe.Pointer(cstr_type))

	err := C.crypt_load(device.device, cstr_type, nil)

	if err < 0 {
		return &Error{functionName: "crypt_load", code: int(err)}
	}

	return nil
}

func (device *Device) Activate(device_name string, keyslot int, passphrase string, flags int) error {
	cstr_device_name := C.CString(device_name)
	defer C.free(unsafe.Pointer(cstr_device_name))

	cstr_passphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cstr_passphrase))

	err := C.crypt_activate_by_passphrase(device.device, cstr_device_name, C.int(keyslot), cstr_passphrase, C.size_t(len(passphrase)), C.uint32_t(flags))

	if err < 0 {
		return &Error{functionName: "crypt_activate_by_passphrase", code: int(err)}
	}

	return nil
}
