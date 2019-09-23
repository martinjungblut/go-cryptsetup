package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import "unsafe"

// LUKS1 is the struct used to manipulate LUKS1 devices.
type LUKS1 struct {
	Hash          string
	DataAlignment int
	DataDevice    string
}

// Name returns the LUKS1 device type name as a string.
func (luks1 LUKS1) Name() string {
	return C.CRYPT_LUKS1
}

// Unmanaged is used to specialize LUKS1.
func (luks1 LUKS1) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0, 2)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams C.struct_crypt_params_luks1

	cParams.data_alignment = C.size_t(luks1.DataAlignment)

	cParams.hash = C.CString(luks1.Hash)
	deallocations = append(deallocations, func() {
		C.free(unsafe.Pointer(cParams.hash))
	})

	cParams.data_device = nil
	if luks1.DataDevice != "" {
		cParams.data_device = C.CString(luks1.DataDevice)
		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cParams.data_device))
		})
	}

	return unsafe.Pointer(&cParams), deallocate
}
