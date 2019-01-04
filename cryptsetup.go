package cryptsetup

/*
#cgo LDFLAGS: -lcryptsetup
#include <libcryptsetup.h>
#include <stdlib.h>
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
// Returns a pointer to the newly allocated Device or any error encountered.
// C equivalent: crypt_init
func Init(devicePath string) (*Device, error) {
	cDevicePath := C.CString(devicePath)
	defer C.free(unsafe.Pointer(cDevicePath))

	var cDevice *C.struct_crypt_device

	err := int(C.crypt_init(&cDevice, cDevicePath))
	if err < 0 {
		return nil, &Error{functionName: "crypt_init", code: err}
	}

	return &Device{cDevice: cDevice}, nil
}

// Format formats a Device, using a type-specific TypeParams parameter and a type-agnostic GenericParams parameter.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_format
func (device *Device) Format(typeParams TypeParams, genericParams *GenericParams) error {
	typeParams.FillDefaultValues()
	genericParams.FillDefaultValues()

	cType := C.CString(typeParams.Type())
	defer C.free(unsafe.Pointer(cType))

	cCipher := C.CString(genericParams.Cipher)
	defer C.free(unsafe.Pointer(cCipher))

	cCipherMode := C.CString(genericParams.CipherMode)
	defer C.free(unsafe.Pointer(cCipherMode))

	var cUUID *C.char
	if genericParams.UUID == "" {
		cUUID = nil
	} else {
		cUUID = C.CString(genericParams.UUID)
		defer C.free(unsafe.Pointer(cUUID))
	}

	var cVolumeKey *C.char
	if genericParams.VolumeKey == "" {
		cVolumeKey = nil
	} else {
		cVolumeKey = C.CString(genericParams.VolumeKey)
		defer C.free(unsafe.Pointer(cVolumeKey))
	}

	cVolumeKeySize := C.size_t(genericParams.VolumeKeySize)

	cTypeParams, freeCTypeParams := typeParams.Unmanaged()
	defer freeCTypeParams()

	err := C.crypt_format(device.cPointer(), cType, cCipher, cCipherMode, cUUID, cVolumeKey, cVolumeKeySize, cTypeParams)
	if err < 0 {
		return &Error{functionName: "crypt_format", code: int(err)}
	}

	return nil
}

// Load loads crypt device parameters from the on-disk header. A TypeParams parameter must be provided, indicating the device's type.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_load
func (device *Device) Load(typeParams TypeParams) error {
	cType := C.CString(typeParams.Type())
	defer C.free(unsafe.Pointer(cType))

	err := C.crypt_load(device.cDevice, cType, nil)
	if err < 0 {
		return &Error{functionName: "crypt_load", code: int(err)}
	}

	return nil
}

// AddPassphraseByVolumeKey adds a passphrase to a keyslot, using a volume key to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_add_by_volume_key
func (device *Device) AddPassphraseByVolumeKey(keyslot int, volumeKey string, passphrase string) error {
	var cVolumeKey *C.char
	if volumeKey == "" {
		cVolumeKey = nil
	} else {
		cVolumeKey = C.CString(volumeKey)
		defer C.free(unsafe.Pointer(cVolumeKey))
	}

	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	err := C.crypt_keyslot_add_by_volume_key(device.cPointer(), C.int(keyslot), cVolumeKey, C.size_t(len(volumeKey)), cPassphrase, C.size_t(len(passphrase)))
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_volume_key", code: int(err)}
	}

	return nil
}

// ActivateByPassphrase activates a device by using a passphrase from a specific keyslot.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_passphrase
func (device *Device) ActivateByPassphrase(deviceName string, keyslot int, passphrase string, flags int) error {
	cDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cDeviceName))

	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	err := C.crypt_activate_by_passphrase(device.cPointer(), cDeviceName, C.int(keyslot), cPassphrase, C.size_t(len(passphrase)), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_passphrase", code: int(err)}
	}

	return nil
}
