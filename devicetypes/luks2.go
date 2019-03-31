package devicetypes

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
import "C"
import "unsafe"

// LUKS2 is the struct used to manipulate LUKS2 devices.
type LUKS2 struct {
	PBKDFType       PbkdfType
	Integrity       string
	IntegrityParams IntegrityParams
	DataAlignment   int
	DataDevice      string
	SectorSize      uint32
	Label           string
	Subsystem       string
}

type PbkdfType struct {
	Type            string
	Hash            string
	TimeMs          uint32
	Iterations      uint32
	MaxMemoryKb     uint32
	ParallelThreads uint32
	Flags           uint32
}

type IntegrityParams struct {
	JournalSize             uint64
	JournalWatermark        uint
	JournalCommitTime       uint
	InterleaveSectors       uint32
	TagSize                 uint32
	SectorSize              uint32
	BufferSectors           uint32
	Integrity               string
	IntegrityKeySize        uint32

	JournalIntegrity        string
	JournalIntegrityKey     string
	JournalIntegrityKeySize uint32

	JournalCrypt            string
	JournalCryptKey         string
	JournalCryptKeySize     uint32
}

// DefaultLUKS2 creates a new LUKS2 struct with fail-safe default values.
// Hash is set to "sha256".
func DefaultLUKS2() *LUKS2 {
	luks2 := new(LUKS2)

	luks2.SectorSize = 512

	return luks2
}

// Type returns the LUKS2 type as a string.
func (luks2 LUKS2) Type() string {
	return C.CRYPT_LUKS2
}

// Unmanaged is used to specialize LUKS2.
func (luks2 LUKS2) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0, 4)
	deallocate := func() {
		for index := 0; index < len(deallocations); index++ {
			deallocations[index]()
		}
	}

	var cParams C.struct_crypt_params_luks2

	cParams.integrity = nil
	if luks2.Integrity != "" {
		cParams.integrity = C.CString(luks2.Integrity)
		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cParams.integrity))
		})
	}

	cParams.data_alignment = C.size_t(luks2.DataAlignment)

	cParams.data_device = nil
	if luks2.DataDevice != "" {
		cParams.data_device = C.CString(luks2.DataDevice)
		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cParams.data_device))
		})
	}

	cParams.sector_size = C.uint32_t(luks2.SectorSize)

	cParams.label = nil
	if luks2.Label != "" {
		cParams.label = C.CString(luks2.Label)
		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cParams.label))
		})
	}

	cParams.subsystem = nil
	if luks2.Subsystem != "" {
		cParams.subsystem = C.CString(luks2.Subsystem)
		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cParams.subsystem))
		})
	}

	return unsafe.Pointer(&cParams), deallocate
}

func (luks2 LUKS2) Supports() supportedOperations {
	return supportedOperations{
		KeyslotAddByPassphrase: true,
		KeyslotAddByVolumeKey: true,
		KeyslotChangeByPassphrase: true,
		Load: true,
	}
}
