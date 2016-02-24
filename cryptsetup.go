package main

/*
#cgo CFLAGS: -O3
#cgo LDFLAGS: -lcryptsetup
#include <libcryptsetup.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type Node struct {
	Name string
	Path string
	Passphrase string
	device *C.struct_crypt_device
}

type Error struct {
	message string
	code int
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %d", e.message, e.code)
}

func Load_Node(name string, path string, passphrase string, nodes *[]Node) (error) {
	var device *C.struct_crypt_device
	c_path := C.CString(path)
	c_crypt_luks := C.CString(C.CRYPT_LUKS1)
	c_name := C.CString(name)
	c_passphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(c_path))
	defer C.free(unsafe.Pointer(c_crypt_luks))
	defer C.free(unsafe.Pointer(c_name))
	defer C.free(unsafe.Pointer(c_passphrase))

	err := C.crypt_init(&device, c_path)
	if err < 0 {
		return &Error{message: "crypt_init", code: int(err)}
	}
	defer C.crypt_free(device)

	err = C.crypt_load(device, c_crypt_luks, nil)
	if err < 0 {
		return &Error{message: "crypt_load", code: int(err)}
	}

	err = C.crypt_activate_by_passphrase(device, c_name, C.CRYPT_ANY_SLOT,
		c_passphrase, C.size_t(len(passphrase)), 0)
	if err < 0 && err != -17 {
		return &Error{message: "crypt_activate_by_passphrase", code: int(err)}
	}

	node := Node{Name: name, Path: path, Passphrase: passphrase, device: device}
	*nodes = append(*nodes, node)

	return nil
}

func Unload_Nodes(nodes []Node) (error) {
	for _, node := range nodes {
		name := C.CString(node.Name)
		defer C.free(unsafe.Pointer(name))

		err := C.crypt_deactivate(node.device, name)
		if err < 0 {
			return &Error{message: "crypt_deactivate", code: int(err)}
		}

		// crypt_free() is raising a SIGPANIC, so it is commented for now
		// C.crypt_free(node.device)
	}

	return nil
}
