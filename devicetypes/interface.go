package devicetypes

import "unsafe"

type supportedOperations struct {
	KeyslotAddByPassphrase bool
	KeyslotAddByVolumeKey bool
	Load bool
}

// Interface that all device types must implement.
type Interface interface {
	Type() string
	Unmanaged() (unsafe.Pointer, func())
	Supports() supportedOperations
}
