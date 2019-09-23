package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import "unsafe"

type Plain struct {
	Hash       string
	Offset     uint64
	Skip       uint64
	Size       uint64
	SectorSize uint32
}

// Name returns the PLAIN device type name as a string.
func (plain Plain) Name() string {
	return "PLAIN"
}

func (plain Plain) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0, 1)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams C.struct_crypt_params_plain

	cParams.offset = C.uint64_t(plain.Offset)
	cParams.skip = C.uint64_t(plain.Skip)
	cParams.size = C.uint64_t(plain.Size)
	cParams.sector_size = C.uint32_t(plain.SectorSize)

	cParams.hash = C.CString(plain.Hash)
	deallocations = append(deallocations, func() {
		C.free(unsafe.Pointer(cParams.hash))
	})

	return unsafe.Pointer(&cParams), deallocate
}
