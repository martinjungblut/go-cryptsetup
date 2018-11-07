package cryptsetup

/*
#include <libcryptsetup.h>
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

// Device is a handle to the crypto device.
// It encapsulates libcryptsetup's 'crypt_device' struct.
type Device struct {
	device *C.struct_crypt_device
}
