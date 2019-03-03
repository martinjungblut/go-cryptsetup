package cryptsetup

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
