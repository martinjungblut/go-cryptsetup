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

// InitByName initializes a crypt device from provided active device 'name'.
// Returns a pointer to the newly allocated Device or any error encountered.
// C equivalent: crypt_init_by_name
func InitByName(name string) (*Device, error) {
	activeCryptDeviceName := C.CString(name)
	defer C.free(unsafe.Pointer(activeCryptDeviceName))

	var cryptDevice *C.struct_crypt_device
	if err := int(C.crypt_init_by_name(&cryptDevice, activeCryptDeviceName)); err < 0 {
		return nil, &Error{functionName: "crypt_init_by_name", code: err}
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

// Resize the crypt device.
// Set newSize to 0 to use all of the underlying device size
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_resize
func (device *Device) Resize(name string, newSize uint64) error {
	cryptDeviceName := C.CString(name)
	defer C.free(unsafe.Pointer(cryptDeviceName))

	err := C.crypt_resize(device.cryptDevice, cryptDeviceName, C.uint64_t(newSize))
	if err < 0 {
		return &Error{functionName: "crypt_resize", code: int(err)}
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
// If deviceName is empty only check passphrase.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_passphrase
func (device *Device) ActivateByPassphrase(deviceName string, keyslot int, passphrase string, flags int) error {
	var cryptDeviceName *C.char = nil
	if len(deviceName) > 0 {
		cryptDeviceName = C.CString(deviceName)
		defer C.free(unsafe.Pointer(cryptDeviceName))
	}

	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	err := C.crypt_activate_by_passphrase(device.cryptDevice, cryptDeviceName, C.int(keyslot), cPassphrase, C.size_t(len(passphrase)), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_passphrase", code: int(err)}
	}

	return nil
}

// ActivateByToken activates a device or checks key using a token.
// C equivalent: crypt_activate_by_token
func (device *Device) ActivateByToken(deviceName string, token int, usrptr string, flags int) error {
	var cryptDeviceName *C.char = nil
	if len(deviceName) > 0 {
		cryptDeviceName = C.CString(deviceName)
		defer C.free(unsafe.Pointer(cryptDeviceName))
	}

	var cUsrptr *C.char = nil
	if len(usrptr) > 0 {
		cUsrptr = C.CString(usrptr)
		defer C.free(unsafe.Pointer(cUsrptr))
	}

	err := C.crypt_activate_by_token(device.cryptDevice, cryptDeviceName, C.int(token), unsafe.Pointer(cUsrptr), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_token", code: int(err)}
	}
	return nil
}

// ActivateByVolumeKey activates a device by using a volume key.
// If deviceName is empty only check passphrase.
// Returns nil on success, or an error otherwise.
// C equivalent: crypt_activate_by_volume_key
func (device *Device) ActivateByVolumeKey(deviceName string, volumeKey string, volumeKeySize int, flags int) error {
	var cryptDeviceName *C.char = nil
	if len(deviceName) > 0 {
		cryptDeviceName = C.CString(deviceName)
		defer C.free(unsafe.Pointer(cryptDeviceName))
	}

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

// GetDeviceName gets the path to the underlying device.
// C equivalent: crypt_get_device_name
func (device *Device) GetDeviceName() string {
	res := C.crypt_get_device_name(device.cryptDevice)
	return C.GoString(res)
}

// GetUUID gets the device's UUID.
// C equivalent: crypt_get_uuid
func (device *Device) GetUUID() string {
	res := C.crypt_get_uuid(device.cryptDevice)
	return C.GoString(res)
}

// TokenJSONGet gets content of a token definition in JSON format.
// C equivalent: crypt_token_json_get
func (device *Device) TokenJSONGet(token int) (string, error) {
	cStr := C.CString("")
	defer C.free(unsafe.Pointer(cStr))

	if res := C.crypt_token_json_get(device.cryptDevice, C.int(token), &cStr); res < 0 {
		return "", &Error{functionName: "crypt_token_json_get", code: int(res)}
	}

	return C.GoString(cStr), nil
}

// TokenJSONSet stores content of a token definition in JSON format.
// Use CRYPT_ANY_TOKEN to allocate new one.
// Returns allocated token ID on success, or an error otherwise.
// C equivalent: crypt_token_json_set
func (device *Device) TokenJSONSet(token int, json string) (int, error) {
	cStr := C.CString(json)
	defer C.free(unsafe.Pointer(cStr))

	res := C.crypt_token_json_set(device.cryptDevice, C.int(token), cStr)
	if res < 0 {
		return -1, &Error{functionName: "crypt_token_json_set", code: int(res)}
	}
	return int(res), nil
}

// TokenLUKS2KeyRingGet gets LUKS2 keyring token params.
// C equivalent: crypt_token_luks2_keyring_get
func (device *Device) TokenLUKS2KeyRingGet(token int) (TokenParamsLUKS2Keyring, error) {
	cParams := (*C.struct_crypt_token_params_luks2_keyring)(C.malloc(C.sizeof_struct_crypt_token_params_luks2_keyring))
	defer C.free(unsafe.Pointer(cParams))

	res := C.crypt_token_luks2_keyring_get(device.cryptDevice, C.int(token), cParams)
	if res < 0 {
		return TokenParamsLUKS2Keyring{}, &Error{functionName: "crypt_token_luks2_keyring_get", code: int(res)}
	}

	return TokenParamsLUKS2Keyring{
		KeyDescription: C.GoString(cParams.key_description),
	}, nil
}

// TokenLUKS2KeyRingSet creates a new luks2 keyring token.
// C equivalent: crypt_token_luks2_keyring_set
func (device *Device) TokenLUKS2KeyRingSet(token int, params TokenParamsLUKS2Keyring) (int, error) {
	cKeyDescription := C.CString(params.KeyDescription)
	defer C.free(unsafe.Pointer(cKeyDescription))
	cParams := (*C.struct_crypt_token_params_luks2_keyring)(C.malloc(C.sizeof_struct_crypt_token_params_luks2_keyring))
	defer C.free(unsafe.Pointer(cParams))
	cParams.key_description = cKeyDescription

	res := C.crypt_token_luks2_keyring_set(device.cryptDevice, C.int(token), cParams)
	if res < 0 {
		return -1, &Error{functionName: "crypt_token_luks2_keyring_set", code: int(res)}
	}
	return int(res), nil
}

// TokenAssignKeyslot assigns a token to particular keyslot. (There can be more keyslots assigned to one token id.)
// Use CRYPT_ANY_TOKEN to assign all tokens to keyslot.
// Use CRYPT_ANY SLOT to assign all active keyslots to token.
// C equivalent: crypt_token_assign_keyslot
func (device *Device) TokenAssignKeyslot(token int, keyslot int) error {
	res := C.crypt_token_assign_keyslot(device.cryptDevice, C.int(token), C.int(keyslot))

	// libcryptsetup returns the token ID on success
	// In case of CRYPT_ANY_TOKEN, the token ID is -1,
	// so we need to make sure the response is actually an error instead of a token ID
	resAnyToken := token == CRYPT_ANY_TOKEN && int(res) == token
	if res < 0 && !resAnyToken {
		return &Error{functionName: "crypt_token_assign_keyslot", code: int(res)}
	}
	return nil
}

// TokenUnassignKeyslot unassigns a token from particular keyslot.
// There can be more keyslots assigned to one token id.
// Use CRYPT_ANY_TOKEN to unassign all tokens from keyslot.
// Use CRYPT_ANY SLOT to unassign all active keyslots from token.
// C equivalent: crypt_token_unassign_keyslot
func (device *Device) TokenUnassignKeyslot(token int, keyslot int) error {
	res := C.crypt_token_unassign_keyslot(device.cryptDevice, C.int(token), C.int(keyslot))
	resAnyToken := token == CRYPT_ANY_TOKEN && int(res) == token
	if res < 0 && !resAnyToken {
		return &Error{functionName: "crypt_token_assign_keyslot", code: int(res)}
	}
	return nil
}

// TokenIsAssigned gets info about token assignment to particular keyslot.
// C equivalent: crypt_token_is_assigned
func (device *Device) TokenIsAssigned(token int, keyslot int) error {
	if res := C.crypt_token_is_assigned(device.cryptDevice, C.int(token), C.int(keyslot)); res < 0 {
		return &Error{functionName: "crypt_token_is_assigned", code: int(res)}
	}
	return nil
}
