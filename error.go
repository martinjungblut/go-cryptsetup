package cryptsetup

import (
	"fmt"
	"syscall"
)

// Error holds the name and the return value of a libcryptsetup function that was executed with an error.
type Error struct {
	code         int
	functionName string
}

func (e *Error) Error() string {
	code := e.code
	if code < 0 {
		code = -code
	}
	return fmt.Sprintf("libcryptsetup function '%s' returned error with code '%d': %s.", e.functionName, e.code, syscall.Errno(code).Error())
}

// Code returns the error code returned by a libcryptsetup function.
func (e *Error) Code() int {
	return e.code
}
