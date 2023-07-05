//go:build cryptsetup2.4

package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"

import (
	"unsafe"
)

// DumpJSON returns JSON-formatted information about a LUKS2 device.
// C equivalent: crypt_dump_json
func (device *Device) DumpJSON() (string, error) {
	cStr := C.CString("")
	defer C.free(unsafe.Pointer(cStr))

	// crypt_dump_json does not support flags currently, but they are reserved for future use.
	if res := C.crypt_dump_json(device.cryptDevice, &cStr, C.uint32_t(0)); res != 0 {
		return "", &Error{functionName: "crypt_dump_json", code: int(res)}
	}
	return C.GoString(cStr), nil
}

// ActivateByTokenPin activates a device or checks key using a token with PIN.
// C equivalent: crypt_activate_by_token_pin
func (device *Device) ActivateByTokenPin(deviceName string, tokenType string, token int, pin string, pinSize int, usrptr string, flags int) error {
	var cryptDeviceName *C.char = nil
	if len(deviceName) > 0 {
		cryptDeviceName = C.CString(deviceName)
		defer C.free(unsafe.Pointer(cryptDeviceName))
	}

	var cTokenType *C.char = nil
	if len(tokenType) > 0 {
		cTokenType = C.CString(tokenType)
		defer C.free(unsafe.Pointer(cTokenType))
	}

	var cPin *C.char = nil
	if len(pin) > 0 {
		cPin = C.CString(pin)
		defer C.free(unsafe.Pointer(cPin))
	}

	var cUsrptr *C.char = nil
	if len(usrptr) > 0 {
		cUsrptr = C.CString(usrptr)
		defer C.free(unsafe.Pointer(cUsrptr))
	}

	err := C.crypt_activate_by_token_pin(device.cryptDevice, cryptDeviceName, cTokenType, C.int(token), cPin, C.size_t(pinSize), unsafe.Pointer(cUsrptr), C.uint32_t(flags))
	if err < 0 {
		return &Error{functionName: "crypt_activate_by_token_pin", code: int(err)}
	}
	return nil
}

// TokenExternalDisable disables external token handlers (plugins) support.
// If disabled, it cannot be enabled again.
// C equivalent: crypt_token_external_disable
func TokenExternalDisable() {
	C.crypt_token_external_disable()
}

// TokenExternalPath reports configured path where library searches for external token handlers.
// C equivalent: crypt_token_external_path
func TokenExternalPath() string {
	res := C.crypt_token_external_path()
	return C.GoString(res)
}

// TokenMax gets the number of tokens supported for device type.
// Returns token count or negative errno otherwise if device doesn't not support tokens
// C equivalent: crypt_token_max
func TokenMax(deviceType DeviceType) int {
	cType := C.CString(deviceType.Name())
	defer C.free(unsafe.Pointer(cType))

	return int(C.crypt_token_max(cType))
}
