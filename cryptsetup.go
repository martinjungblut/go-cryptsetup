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
	"fmt"
	"unsafe"
)

type Error struct {
	code int
	function string
}

type LUKSParams struct {
	Data_alignment int
	Data_device, Hash string
}

type LoopAESParams struct {
	hash string
	offset, skip int
}

type CryptDevice struct {
	device *C.struct_crypt_device
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s returned error with code %d", e.function, e.code)
}

func Init(device string) (error, *CryptDevice) {
	c_device := C.CString(device)
	defer C.free(unsafe.Pointer(c_device))

	var c_cd *C.struct_crypt_device

	err := C.crypt_init(&c_cd, c_device)
	if err < 0 {
		return &Error{function: "crypt_init", code: int(err)}, nil
	}

	return nil, &CryptDevice{device: c_cd}
}

func (device *CryptDevice) FormatLUKS(cipher string, cipher_mode string, uuid string, volume_key string, volume_key_size int, params LUKSParams) (error) {
	cstr_type := C.CString(C.CRYPT_LUKS1)
	defer C.free(unsafe.Pointer(cstr_type))

	cstr_cipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(cstr_cipher))

	cstr_cipher_mode := C.CString(cipher_mode)
	defer C.free(unsafe.Pointer(cstr_cipher_mode))

	var cstr_uuid *C.char
	if (uuid == "") {
	    cstr_uuid = nil
	} else {
	    cstr_uuid = C.CString(uuid)
	    defer C.free(unsafe.Pointer(cstr_uuid))
	}

	var cstr_volume_key *C.char
	if (volume_key == "") {
	    cstr_volume_key = nil
	} else {
	    cstr_volume_key = C.CString(volume_key)
	    defer C.free(unsafe.Pointer(cstr_volume_key))
	}

	var c_params C.struct_crypt_params_luks1
	c_params.data_alignment = C.size_t(params.data_alignment)
	c_params.hash = C.CString(params.hash)
	if params.data_device != "" {
	    c_params.data_device = C.CString(params.data_device)
	} else {
	    c_params.data_device = nil
	}

	err := C.crypt_format(device.device, cstr_type, cstr_cipher, cstr_cipher_mode, cstr_uuid, cstr_volume_key, C.size_t(volume_key_size), unsafe.Pointer(&c_params))
	if err < 0 {
		return &Error{function: "crypt_format", code: int(err)}
	}

	return nil
}
