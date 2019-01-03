package cryptsetup

import "fmt"

// Error holds the name and the return value of a libcryptsetup function that was executed with an error.
type Error struct {
	code         int
	functionName string
}

func (e *Error) Error() string {
	return fmt.Sprintf("libcryptsetup function '%s' returned error with code '%d'.", e.functionName, e.code)
}

// Code returns the error code returned by a libcryptsetup function.
func (e *Error) Code() int {
	return e.code
}
