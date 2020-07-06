package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

// Device is a handle to the crypto device.
// It encapsulates libcryptsetup's 'crypt_device' struct.
type Device struct {
	cryptDevice *C.struct_crypt_device
	freed       bool
}

// Init initializes a crypt device backed by 'devicePath'.
// Returns a pointer to the newly allocated Device or any error encountered.
// C equivalent: crypt_init
func Init(devicePath string) (*Device, error) {
	cryptDevicePath := C.CString(devicePath)
	defer C.free(unsafe.Pointer(cryptDevicePath))

	var cryptDevice *C.struct_crypt_device
	if err := int(C.crypt_init(&cryptDevice, cryptDevicePath)); err < 0 {
		return nil, &Error{functionName: "crypt_init", code: err}
	}

	return &Device{cryptDevice: cryptDevice}, nil
}

// Free releases crypt device context and used memory.
// C equivalent: crypt_free
func (device *Device) Free() bool {
	if device.freed == false {
		C.crypt_free(device.cryptDevice)
		device.freed = true
		return true
	}
	return false
}

// C equivalent: crypt_dump
func (device *Device) Dump() int {
	return int(C.crypt_dump(device.cryptDevice))
}

// Type returns the device's type as a string.
// Returns an empty string if the information is not available.
func (device *Device) Type() string {
	return C.GoString(C.crypt_get_type(device.cryptDevice))
}

// Format formats a Device, using a specific device type, and type-independent parameters.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_format
func (device *Device) Format(deviceType DeviceType, genericParams GenericParams) error {
	cryptDeviceTypeName := C.CString(deviceType.Name())
	defer C.free(unsafe.Pointer(cryptDeviceTypeName))

	cCipher := C.CString(genericParams.Cipher)
	defer C.free(unsafe.Pointer(cCipher))

	cCipherMode := C.CString(genericParams.CipherMode)
	defer C.free(unsafe.Pointer(cCipherMode))

	var cUUID *C.char = nil
	if len(genericParams.UUID) > 0 {
		cUUID = C.CString(genericParams.UUID)
		defer C.free(unsafe.Pointer(cUUID))
	}

	var cVolumeKey *C.char = nil
	if len(genericParams.VolumeKey) > 0 {
		cVolumeKey = C.CString(genericParams.VolumeKey)
		defer C.free(unsafe.Pointer(cVolumeKey))
	}

	cVolumeKeySize := C.size_t(genericParams.VolumeKeySize)

	cTypeParams, freeCTypeParams := deviceType.Unmanaged()
	defer freeCTypeParams()

	err := C.crypt_format(device.cryptDevice, cryptDeviceTypeName, cCipher, cCipherMode, cUUID, cVolumeKey, cVolumeKeySize, cTypeParams)
	if err < 0 {
		return &Error{functionName: "crypt_format", code: int(err)}
	}

	return nil
}

// Load loads crypt device parameters from the on-disk header.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_load
func (device *Device) Load() error {
	err := C.crypt_load(device.cryptDevice, nil, nil)
	if err < 0 {
		return &Error{functionName: "crypt_load", code: int(err)}
	}

	return nil
}

// KeyslotAddByVolumeKey adds a key slot using a volume key to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_add_by_volume_key
func (device *Device) KeyslotAddByVolumeKey(keyslot int, volumeKey string, passphrase string) error {
	var cVolumeKey *C.char = nil
	if len(volumeKey) > 0 {
		cVolumeKey = C.CString(volumeKey)
		defer C.free(unsafe.Pointer(cVolumeKey))
	}

	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	err := C.crypt_keyslot_add_by_volume_key(device.cryptDevice, C.int(keyslot), cVolumeKey, C.size_t(len(volumeKey)), cPassphrase, C.size_t(len(passphrase)))
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_volume_key", code: int(err)}
	}

	return nil
}

// KeyslotAddByPassphrase adds a key slot using a previously added passphrase to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_add_by_passphrase
func (device *Device) KeyslotAddByPassphrase(keyslot int, currentPassphrase string, newPassphrase string) error {
	cCurrentPassphrase := C.CString(currentPassphrase)
	defer C.free(unsafe.Pointer(cCurrentPassphrase))

	cNewPassphrase := C.CString(newPassphrase)
	defer C.free(unsafe.Pointer(cNewPassphrase))

	err := C.crypt_keyslot_add_by_passphrase(
		device.cryptDevice, C.int(keyslot),
		cCurrentPassphrase, C.size_t(len(currentPassphrase)),
		cNewPassphrase, C.size_t(len(newPassphrase)),
	)
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_passphrase", code: int(err)}
	}

	return nil
}

// KeyslotChangeByPassphrase changes a defined a key slot using a previously added passphrase to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_change_by_passphrase
func (device *Device) KeyslotChangeByPassphrase(currentKeyslot int, newKeyslot int, currentPassphrase string, newPassphrase string) error {
	cCurrentPassphrase := C.CString(currentPassphrase)
	defer C.free(unsafe.Pointer(cCurrentPassphrase))

	cNewPassphrase := C.CString(newPassphrase)
	defer C.free(unsafe.Pointer(cNewPassphrase))

	err := C.crypt_keyslot_change_by_passphrase(
		device.cryptDevice,
		C.int(currentKeyslot),
		C.int(newKeyslot),
		cCurrentPassphrase, C.size_t(len(currentPassphrase)),
		cNewPassphrase, C.size_t(len(newPassphrase)),
	)
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_change_by_passphrase", code: int(err)}
	}

	return nil
}

// ActivateByPassphrase activates a device by using a passphrase from a specific keyslot.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_passphrase
func (device *Device) ActivateByPassphrase(deviceName string, keyslot int, passphrase string, flags int) error {
	cryptDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cryptDeviceName))

	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	err := C.crypt_activate_by_passphrase(device.cryptDevice, cryptDeviceName, C.int(keyslot), cPassphrase, C.size_t(len(passphrase)), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_passphrase", code: int(err)}
	}

	return nil
}

// ActivateByVolumeKey activates a device by using a volume key.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_volume_key
func (device *Device) ActivateByVolumeKey(deviceName string, volumeKey string, volumeKeySize int, flags int) error {
	cryptDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cryptDeviceName))

	var cVolumeKey *C.char = nil
	if len(volumeKey) > 0 {
		cVolumeKey = C.CString(volumeKey)
		defer C.free(unsafe.Pointer(cVolumeKey))
	}

	err := C.crypt_activate_by_volume_key(device.cryptDevice, cryptDeviceName, cVolumeKey, C.size_t(volumeKeySize), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_volume_key", code: int(err)}
	}

	return nil
}

// Deactivate deactivates a device.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_deactivate
func (device *Device) Deactivate(deviceName string) error {
	cryptDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cryptDeviceName))

	err := C.crypt_deactivate(device.cryptDevice, cryptDeviceName)
	if err < 0 {
		return &Error{functionName: "crypt_deactivate", code: int(err)}
	}

	return nil
}

// SetDebugLevel sets the debug level for the library.
// C equivalent: crypt_set_debug_level
func SetDebugLevel(debugLevel int) {
	C.crypt_set_debug_level(C.int(debugLevel))
}
