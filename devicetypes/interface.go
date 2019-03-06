package devicetypes

import "unsafe"

// Interface that all device types must implement.
type Interface interface {
	Type() string
	Unmanaged() (unsafe.Pointer, func())
}
