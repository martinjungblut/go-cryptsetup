package cryptsetup

import "unsafe"

// Interface that all device types must implement.
type DeviceType interface {
	Name() string
	Unmanaged() (unsafe.Pointer, func())
}
