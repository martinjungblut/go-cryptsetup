package cryptsetup

// #cgo pkg-config: libcryptsetup
// #include <libcryptsetup.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import "unsafe"

// LUKS2 is the struct used to manipulate LUKS2 devices.
type LUKS2 struct {
	PBKDFType       *PbkdfType
	Integrity       string
	IntegrityParams *IntegrityParams
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
	JournalSize       uint64
	JournalWatermark  uint
	JournalCommitTime uint

	InterleaveSectors uint32
	TagSize           uint32
	SectorSize        uint32
	BufferSectors     uint32

	Integrity        string
	IntegrityKeySize uint32

	JournalIntegrity        string
	JournalIntegrityKey     string
	JournalIntegrityKeySize uint32

	JournalCrypt        string
	JournalCryptKey     string
	JournalCryptKeySize uint32
}

// Name returns the LUKS2 device type name as a string.
func (luks2 LUKS2) Name() string {
	return C.CRYPT_LUKS2
}

// Unmanaged is used to specialize LUKS2.
func (luks2 LUKS2) Unmanaged() (unsafe.Pointer, func()) {
	deallocations := make([]func(), 0)
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

	cParams.pbkdf = nil
	if luks2.PBKDFType != nil {
		cPBKDFType := (*C.struct_crypt_pbkdf_type)(C.malloc(C.sizeof_struct_crypt_pbkdf_type))

		cPBKDFType._type = nil
		if luks2.PBKDFType.Type != "" {
			cPBKDFType._type = C.CString(luks2.PBKDFType.Type)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cPBKDFType._type))
			})
		}

		cPBKDFType.hash = nil
		if luks2.PBKDFType.Hash != "" {
			cPBKDFType.hash = C.CString(luks2.PBKDFType.Hash)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cPBKDFType.hash))
			})
		}

		cPBKDFType.time_ms = C.uint32_t(luks2.PBKDFType.TimeMs)
		cPBKDFType.iterations = C.uint32_t(luks2.PBKDFType.Iterations)
		cPBKDFType.max_memory_kb = C.uint32_t(luks2.PBKDFType.MaxMemoryKb)
		cPBKDFType.parallel_threads = C.uint32_t(luks2.PBKDFType.ParallelThreads)
		cPBKDFType.flags = C.uint32_t(luks2.PBKDFType.Flags)

		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cPBKDFType))
		})

		cParams.pbkdf = cPBKDFType
	}

	cParams.integrity_params = nil
	if luks2.IntegrityParams != nil {
		cIntegrityParams := (*C.struct_crypt_params_integrity)(C.malloc(C.sizeof_struct_crypt_params_integrity))

		cIntegrityParams.journal_size = C.uint64_t(luks2.IntegrityParams.JournalSize)
		cIntegrityParams.journal_watermark = C.uint(luks2.IntegrityParams.JournalWatermark)
		cIntegrityParams.journal_commit_time = C.uint(luks2.IntegrityParams.JournalCommitTime)

		cIntegrityParams.interleave_sectors = C.uint32_t(luks2.IntegrityParams.InterleaveSectors)
		cIntegrityParams.tag_size = C.uint32_t(luks2.IntegrityParams.TagSize)
		cIntegrityParams.sector_size = C.uint32_t(luks2.IntegrityParams.SectorSize)
		cIntegrityParams.buffer_sectors = C.uint32_t(luks2.IntegrityParams.BufferSectors)

		cIntegrityParams.integrity = nil
		if luks2.IntegrityParams.Integrity != "" {
			cIntegrityParams.integrity = C.CString(luks2.IntegrityParams.Integrity)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cIntegrityParams.integrity))
			})
		}
		cIntegrityParams.integrity_key_size = C.uint32_t(luks2.IntegrityParams.IntegrityKeySize)

		cIntegrityParams.journal_integrity = nil
		if luks2.IntegrityParams.JournalIntegrity != "" {
			cIntegrityParams.journal_integrity = C.CString(luks2.IntegrityParams.JournalIntegrity)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cIntegrityParams.journal_integrity))
			})
		}
		cIntegrityParams.journal_integrity_key = nil
		if luks2.IntegrityParams.JournalIntegrityKey != "" {
			cIntegrityParams.journal_integrity_key = C.CString(luks2.IntegrityParams.JournalIntegrityKey)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cIntegrityParams.journal_integrity_key))
			})
		}
		cIntegrityParams.journal_integrity_key_size = C.uint32_t(luks2.IntegrityParams.JournalIntegrityKeySize)

		cIntegrityParams.journal_crypt = nil
		if luks2.IntegrityParams.JournalCrypt != "" {
			cIntegrityParams.journal_crypt = C.CString(luks2.IntegrityParams.JournalCrypt)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cIntegrityParams.journal_crypt))
			})
		}
		cIntegrityParams.journal_crypt_key = nil
		if luks2.IntegrityParams.JournalCryptKey != "" {
			cIntegrityParams.journal_crypt_key = C.CString(luks2.IntegrityParams.JournalCryptKey)
			deallocations = append(deallocations, func() {
				C.free(unsafe.Pointer(cIntegrityParams.journal_crypt_key))
			})
		}
		cIntegrityParams.journal_crypt_key_size = C.uint32_t(luks2.IntegrityParams.JournalCryptKeySize)

		deallocations = append(deallocations, func() {
			C.free(unsafe.Pointer(cIntegrityParams))
		})

		cParams.integrity_params = cIntegrityParams
	}

	return unsafe.Pointer(&cParams), deallocate
}
