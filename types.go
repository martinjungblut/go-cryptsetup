package cryptsetup

/*
#include <libcryptsetup.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// Device is a handle to the crypto device.
// It encapsulates libcryptsetup's 'crypt_device' struct.
type Device struct {
	cDevice *C.struct_crypt_device
}

func (device *Device) cPointer() *C.struct_crypt_device {
	return device.cDevice
}

// Type returns the device's type as a string.
// Returns an empty string if the information is not available.
func (device *Device) Type() string {
	return C.GoString(C.crypt_get_type(device.cPointer()))
}

// TypeParams is the interface that all device type specific parameter types must implement.
type TypeParams interface {
	FillDefaultValues()
	Type() string
	Unmanaged() (unsafe.Pointer, func())
}

// GenericParams are device type independent parameters that are used to manipulate devices in various ways.
type GenericParams struct {
	Cipher        string
	CipherMode    string
	UUID          string
	VolumeKey     string
	VolumeKeySize int
}

// FillDefaultValues fills a GenericParams struct with useful default values.
// Cipher is set to "aes".
// CipherMode is set to "xts-plain64".
// VolumeKeySize is set to 256 / 8.
func (p *GenericParams) FillDefaultValues() {
	if p.Cipher == "" {
		p.Cipher = "aes"
	}

	if p.CipherMode == "" {
		p.CipherMode = "xts-plain64"
	}

	if p.VolumeKeySize == 0 {
		p.VolumeKeySize = 256 / 8
	}
}

// LUKS1Params are parameters used to manipulate LUKS1 devices.
type LUKS1Params struct {
	Hash          string
	DataAlignment int
	DataDevice    string
}

// FillDefaultValues fills a LUKS1Params struct with fail-safe default values.
// Hash is set to "sha256".
func (luksParams *LUKS1Params) FillDefaultValues() {
	if luksParams.Hash == "" {
		luksParams.Hash = "sha256"
	}
}

// Unmanaged is used to specialize LUKS1Params.
func (luksParams LUKS1Params) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0, 2)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams C.struct_crypt_params_luks1

	cParams.data_alignment = C.size_t(luksParams.DataAlignment)

	cParams.hash = C.CString(luksParams.Hash)
	deallocations = append(deallocations, func() {
		C.free(unsafe.Pointer(cParams.hash))
	})

	cParams.data_device = nil
	if luksParams.DataDevice != "" {
		cParams.data_device = C.CString(luksParams.DataDevice)
		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cParams.data_device))
		})
	}

	return unsafe.Pointer(&cParams), deallocate
}

func (luksParams LUKS1Params) Type() string {
	return C.CRYPT_LUKS1
}

// type LoopAESParams struct {
// 	hash         string
// 	offset, skip int
// }
