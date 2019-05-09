package cryptsetup

// GenericParams are device type independent parameters that are used to manipulate devices in various ways.
type GenericParams struct {
	Cipher        string
	CipherMode    string
	UUID          string
	VolumeKey     string
	VolumeKeySize int
}
