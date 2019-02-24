package cryptsetup

/*
#include <libcryptsetup.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// LUKS1Params are parameters used to manipulate LUKS1 devices.
type LUKS1Params struct {
	Hash          string
	DataAlignment int
	DataDevice    string
}

// Type returns the LUKS1 type as a string.
func (luksParams LUKS1Params) Type() string {
	return C.CRYPT_LUKS1
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
