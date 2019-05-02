package cryptsetup

// GenericParams are device type independent parameters that are used to manipulate devices in various ways.
type GenericParams struct {
	Cipher        string
	CipherMode    string
	UUID          string
	VolumeKey     string
	VolumeKeySize int
}

// DefaultGenericParams creates a new GenericParams struct with useful default values.
// Cipher is set to "aes".
// CipherMode is set to "xts-plain64".
// VolumeKeySize is set to 256 / 8.
func DefaultGenericParams() GenericParams {
	params := GenericParams{}

	if params.Cipher == "" {
		params.Cipher = "aes"
	}

	if params.CipherMode == "" {
		params.CipherMode = "xts-plain64"
	}

	if params.VolumeKeySize == 0 {
		params.VolumeKeySize = 256 / 8
	}

	return params
}
