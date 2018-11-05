package cryptsetup

/*
#cgo CFLAGS: -O2
#cgo LDFLAGS: -lcryptsetup
#include <libcryptsetup.h>
#include <stdlib.h>
#include <stdio.h>
*/
import "C"

type LUKSParams struct {
	DataAlignment    int
	DataDevice, Hash string
}

type LoopAESParams struct {
	hash         string
	offset, skip int
}

// Device encapsulates libcryptsetup's 'crypt_device' struct.
type Device struct {
	device *C.struct_crypt_device
}
