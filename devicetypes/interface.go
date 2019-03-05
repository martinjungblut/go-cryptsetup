package devicetypes

import "unsafe"

// Interface that all device types must implement.
type Interface interface {
	Type() string
	FillDefaultValues()
	Unmanaged() (unsafe.Pointer, func())
}
