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
