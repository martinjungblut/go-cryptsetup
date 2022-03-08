package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
//extern int progress_callback(uint64_t size, uint64_t offset, void *usrptr);
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
	if !device.freed {
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

var progressCallback func(size, offset uint64) int

//export progress_callback
func progress_callback(size C.uint64_t, offset C.uint64_t, usrptr unsafe.Pointer) C.int {
	if progressCallback != nil {
		ret := progressCallback(uint64(size), uint64(offset))
		return C.int(ret)
	}
	return 0
}

// Wipe wipes/fills (part of) a device with the selected pattern.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_wipe
func (device *Device) Wipe(devicePath string, pattern int, offset, length uint64, wipeBlockSize, flags int, progress func(size, offset uint64) int) error {
	cWipeBlockSize := C.size_t(wipeBlockSize)

	cDevicePath := C.CString(devicePath)
	defer C.free(unsafe.Pointer(cDevicePath))

	progressCallback = progress

	err := C.crypt_wipe(device.cryptDevice, cDevicePath, 0, C.uint64_t(offset), C.uint64_t(length), cWipeBlockSize, C.uint32_t(flags), (*[0]byte)(C.progress_callback), nil)
	if err < 0 {
		return &Error{functionName: "crypt_wipe", code: int(err)}
	}

	return nil
}

// Load loads crypt device parameters from the device type parameters if it is
// specified, otherwise it loads the device from the on-disk header.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_load
func (device *Device) Load(deviceType DeviceType) error {
	var cryptDeviceTypeName *C.char
	var cTypeParams unsafe.Pointer

	if deviceType != nil {
		cryptDeviceTypeName = C.CString(deviceType.Name())
		defer C.free(unsafe.Pointer(cryptDeviceTypeName))

		var freeCTypeParams func()
		cTypeParams, freeCTypeParams = deviceType.Unmanaged()
		defer freeCTypeParams()
	}

	err := C.crypt_load(device.cryptDevice, cryptDeviceTypeName, cTypeParams)
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

// VolumeKeyGet gets the volume key from a crypt device.
// Returns a slice of bytes having the volume key and the unlocked key slot number, or an error otherwise.
// C equivalent: crypt_volume_key_get
func (device *Device) VolumeKeyGet(keyslot int, passphrase string) ([]byte, int, error) {
	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	cVKSize := C.crypt_get_volume_key_size(device.cryptDevice)
	cVKSizePointer := C.malloc(C.size_t(cVKSize))
	if cVKSizePointer == nil {
		return []byte{}, 0, &Error{functionName: "malloc"}
	}
	defer C.free(cVKSizePointer)

	err := C.crypt_volume_key_get(
		device.cryptDevice, C.int(keyslot),
		(*C.char)(cVKSizePointer), (*C.size_t)(unsafe.Pointer(&cVKSize)),
		cPassphrase, C.size_t(len(passphrase)),
	)
	if err < 0 {
		return []byte{}, 0, &Error{functionName: "crypt_volume_key_get", code: int(err)}
	}
	return C.GoBytes(unsafe.Pointer(cVKSizePointer), C.int(cVKSize)), int(err), nil
}
