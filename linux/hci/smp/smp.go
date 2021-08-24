// Package smp provides ...
package smp

// smb command
const (
	PairingRequest           = 0x01 // Pairing Request LE-U, ACL-U
	PairingResponse          = 0x02 // Pairing Response LE-U, ACL-U
	PairingConfirm           = 0x03 // Pairing Confirm LE-U
	PairingRandom            = 0x04 // Pairing Random LE-U
	PairingFailed            = 0x05 // Pairing Failed LE-U, ACL-U
	EncryptionInformation    = 0x06 // Encryption Information LE-U
	MasterIdentification     = 0x07 // Master Identification LE-U
	IdentiInformation        = 0x08 // Identity Information LE-U, ACL-U
	IdentityAddreInformation = 0x09 // Identity Address Information LE-U, ACL-U
	SigningInformation       = 0x0A // Signing Information LE-U, ACL-U
	SecurityRequest          = 0x0B // Security Request LE-U
	PairingPublicKey         = 0x0C // Pairing Public Key LE-U
	PairingDHKeyCheck        = 0x0D // Pairing DHKey Check LE-U
	PairingKeypress          = 0x0E // Pairing Keypress Notification LE-U

	passkeyIterationCount = 20

	oobData
	oobDataPreset = 0x01

	authReqBondMask = byte(0x03)
	authReqBond     = byte(0x01)
	authReqNoBond   = byte(0x00)
)

// io capability property
const (
	IOCapDisplayOnly     = 0x00
	IOCapDisplayYesNo    = 0x01
	IOCapKeyBoardOnly    = 0x02
	IOCapNoInputNoOutput = 0x03
	IOCapKeyboardDisplay = 0x04
	IOCapReservedStart   = 0x05
)

// Config for manager
type Config struct {
	IOCap       byte
	OOBFlag     byte
	AuthReq     byte
	MaxKeySize  byte
	InitKeyDist byte
	RespKeyDist byte
}

func (conf *Config) toSlice(cmd byte) []byte {
	return []byte{
		cmd,
		conf.IOCap,
		conf.OOBFlag,
		conf.AuthReq,
		conf.MaxKeySize,
		conf.InitKeyDist,
		conf.RespKeyDist,
	}
}

type bondInfo struct {
	longTermKey []byte
	ediv        uint16
	randVal     uint64
	legacy      bool
}

type storage interface {
	Find(addr string) (bondInfo, error)
	Save(string, bondInfo) error
	Exists(addr string) bool
	Delete(addr string) error
}

// Manager smp manager
type Manager struct {
	config Config

	storage  storage
	encypter func(info bondInfo) ([]byte, error)
	// transport
	context *pairingContext
}

// Encrypt encrypt message and send
func (m *Manager) Encrypt() ([]byte, error) {
	return m.encypter(m.context.bond)
}

// PairingState state
type PairingState int

// pairing state
const (
	Init PairingState = iota
	WaitPairingResponse
	WaitPublicKey
	WaitConfirm
	WaitRandom
	WaitDhKeyCheck
	Finished
	Error
)

// AuthData  auth data
type AuthData struct {
	Passkey int
	OOBData []byte
}

// SwapBuf swag buf
func SwapBuf(in []byte) []byte {
	a := make([]byte, 0, len(in))
	a = append(a, in...)
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}

	return a
}
