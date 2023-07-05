package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"

import (
	"unsafe"
)

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
