package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
// #include "log.h"
import "C"
import "unsafe"

var __log_callback func(level int, message string)

//export log_callback
func log_callback(level C.int, message *C.char, usrptr unsafe.Pointer) {
	if __log_callback != nil {
		__log_callback(int(level), C.GoString(message))
	}
}

func SetLogCallback(new_log_callback func(level int, message string)) {
	__log_callback = new_log_callback

	C.crypt_set_log_callback(nil, (*[0]byte)(C.log_callback), nil)
}
