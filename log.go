package cryptsetup

/*
#cgo pkg-config: libcryptsetup
#include <libcryptsetup.h>
#include <stdlib.h>

extern void log_callback(int level, char * message, void * usrptr);
*/
import "C"
import "unsafe"

var logCallback func(level int, message string)

//export log_callback
func log_callback(level C.int, message *C.char, usrptr unsafe.Pointer) {
	if logCallback != nil {
		logCallback(int(level), C.GoString(message))
	}
}

func SetLogCallback(newLogCallback func(level int, message string)) {
	logCallback = newLogCallback

	C.crypt_set_log_callback(nil, (*[0]byte)(C.log_callback), nil)
}
