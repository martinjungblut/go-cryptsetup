package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import (
    "cryptsetup/devicetypes"
    "unsafe"
)

// Device is a handle to the crypto device.
// It encapsulates libcryptsetup's 'crypt_device' struct.
type Device struct {
	cDevice *C.struct_crypt_device
}

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

// Type returns the device's type as a string.
// Returns an empty string if the information is not available.
func (device *Device) Type() string {
	return C.GoString(C.crypt_get_type(device.cDevice))
}

// Format formats a Device, using a specific device type, and type-independent parameters.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_format
func (device *Device) Format(deviceType devicetypes.Interface, genericParams *GenericParams) error {
	cType := C.CString(deviceType.Type())
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

	cTypeParams, freeCTypeParams := deviceType.Unmanaged()
	defer freeCTypeParams()

	err := C.crypt_format(device.cDevice, cType, cCipher, cCipherMode, cUUID, cVolumeKey, cVolumeKeySize, cTypeParams)
	if err < 0 {
		return &Error{functionName: "crypt_format", code: int(err)}
	}

	return nil
}

// Load loads crypt device parameters from the on-disk header.
// A specific device type parameter must be provided, indicating the device's type.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_load
func (device *Device) Load(deviceType devicetypes.Interface) error {
	cType := C.CString(deviceType.Type())
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

	err := C.crypt_keyslot_add_by_volume_key(device.cDevice, C.int(keyslot), cVolumeKey, C.size_t(len(volumeKey)), cPassphrase, C.size_t(len(passphrase)))
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_volume_key", code: int(err)}
	}

	return nil
}

// AddPassphraseByPassphrase adds a passphrase to a keyslot, using a previously added passphrase to perform the required security check.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_keyslot_add_by_passphrase
func (device *Device) AddPassphraseByPassphrase(keyslot int, currentPassphrase string, newPassphrase string) error {
	cCurrentPassphrase := C.CString(currentPassphrase)
	defer C.free(unsafe.Pointer(cCurrentPassphrase))

	cNewPassphrase := C.CString(newPassphrase)
	defer C.free(unsafe.Pointer(cNewPassphrase))

	err := C.crypt_keyslot_add_by_passphrase(
		device.cDevice, C.int(keyslot),
		cCurrentPassphrase, C.size_t(len(currentPassphrase)),
		cNewPassphrase, C.size_t(len(newPassphrase)),
	)
	if err < 0 {
		return &Error{functionName: "crypt_keyslot_add_by_passphrase", code: int(err)}
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

	err := C.crypt_activate_by_passphrase(device.cDevice, cDeviceName, C.int(keyslot), cPassphrase, C.size_t(len(passphrase)), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_passphrase", code: int(err)}
	}

	return nil
}

// Deactivate deactivates a device.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_deactivate
func (device *Device) Deactivate(deviceName string) error {
	cDeviceName := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cDeviceName))

	err := C.crypt_deactivate(device.cDevice, cDeviceName)
	if err < 0 {
		return &Error{functionName: "crypt_deactivate", code: int(err)}
	}

	return nil
}
