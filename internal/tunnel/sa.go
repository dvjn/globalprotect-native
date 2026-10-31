package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/dvjn/globalprotect-native/internal/gp"
)

// ESP next header values: what an ESP packet carries.
const (
	nextHeaderIPv4 = 4
	nextHeaderIPv6 = 41
	// nextHeaderNone marks a dummy packet, which the receiver drops (RFC 4303, section 2.6).
	nextHeaderNone = 59
)

// espHeaderLength is the SPI and the sequence number.
const espHeaderLength = 8

// sa is one direction of an ESP security association in tunnel mode (RFC 4303): AES-CBC with an
// HMAC, or AES-GCM (RFC 4106).
type sa struct {
	spi uint32
	// gcm and salt are set for AES-GCM, block, newHash, integrityKey and icvLength for AES-CBC.
	gcm          cipher.AEAD
	salt         []byte
	block        cipher.Block
	newHash      func() hash.Hash
	integrityKey []byte
	icvLength    int
}

func newSA(config gp.ESPConfig, keys gp.ESPKeys) (*sa, error) {
	association := &sa{spi: keys.SPI}
	switch config.Encryption {
	case "aes-128-gcm", "aes-256-gcm":
		// The key ends with a 32-bit salt, as RFC 4106 specifies.
		if len(keys.EncryptionKey) <= 4 {
			return nil, fmt.Errorf("ESP %s key too short", config.Encryption)
		}
		split := len(keys.EncryptionKey) - 4
		block, err := aes.NewCipher(keys.EncryptionKey[:split])
		if err != nil {
			return nil, err
		}
		if association.gcm, err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
		association.salt = keys.EncryptionKey[split:]
		return association, nil
	case "aes-128-cbc", "aes-256-cbc":
		block, err := aes.NewCipher(keys.EncryptionKey)
		if err != nil {
			return nil, err
		}
		association.block = block
	default:
		return nil, fmt.Errorf("unsupported ESP cipher %q", config.Encryption)
	}

	switch config.Integrity {
	case "sha1":
		association.newHash, association.icvLength = sha1.New, 12
	case "sha256":
		association.newHash, association.icvLength = sha256.New, 16
	case "md5":
		association.newHash, association.icvLength = md5.New, 12
	default:
		return nil, fmt.Errorf("unsupported ESP integrity algorithm %q", config.Integrity)
	}
	association.integrityKey = keys.IntegrityKey
	return association, nil
}

// seal encrypts payload into an ESP packet with sequence number sequence.
func (association *sa) seal(sequence uint32, payload []byte, nextHeader byte) ([]byte, error) {
	alignment := aes.BlockSize
	if association.gcm != nil {
		alignment = 4
	}
	padding := (alignment - (len(payload)+2)%alignment) % alignment
	plaintext := make([]byte, 0, len(payload)+padding+2)
	plaintext = append(plaintext, payload...)
	for i := 1; i <= padding; i++ {
		plaintext = append(plaintext, byte(i))
	}
	plaintext = append(plaintext, byte(padding), nextHeader)

	header := binary.BigEndian.AppendUint32(nil, association.spi)
	header = binary.BigEndian.AppendUint32(header, sequence)

	if association.gcm != nil {
		// The sequence number never repeats under one key, so it serves as the explicit IV.
		iv := binary.BigEndian.AppendUint64(nil, uint64(sequence))
		nonce := append(append([]byte{}, association.salt...), iv...)
		packet := append(header, iv...)
		return association.gcm.Seal(packet, nonce, plaintext, header), nil
	}

	packet := make([]byte, espHeaderLength+aes.BlockSize+len(plaintext), espHeaderLength+aes.BlockSize+len(plaintext)+association.icvLength)
	copy(packet, header)
	iv := packet[espHeaderLength : espHeaderLength+aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(association.block, iv).CryptBlocks(packet[espHeaderLength+aes.BlockSize:], plaintext)
	return append(packet, association.icv(packet)...), nil
}

func (association *sa) icv(authenticated []byte) []byte {
	mac := hmac.New(association.newHash, association.integrityKey)
	mac.Write(authenticated)
	return mac.Sum(nil)[:association.icvLength]
}

var errAuthentication = errors.New("ESP packet failed authentication")

// open checks and decrypts an ESP packet for this SA, returning its sequence number, payload and
// next header. It does not check the sequence number against replays.
func (association *sa) open(packet []byte) (sequence uint32, payload []byte, nextHeader byte, err error) {
	if len(packet) < espHeaderLength || binary.BigEndian.Uint32(packet) != association.spi {
		return 0, nil, 0, errors.New("ESP packet for another SPI")
	}
	sequence = binary.BigEndian.Uint32(packet[4:])

	var plaintext []byte
	if association.gcm != nil {
		const ivLength = 8
		if len(packet) < espHeaderLength+ivLength+association.gcm.Overhead() {
			return 0, nil, 0, errors.New("ESP packet too short")
		}
		nonce := append(append([]byte{}, association.salt...), packet[espHeaderLength:espHeaderLength+ivLength]...)
		plaintext, err = association.gcm.Open(nil, nonce, packet[espHeaderLength+ivLength:], packet[:espHeaderLength])
		if err != nil {
			return 0, nil, 0, errAuthentication
		}
	} else {
		body := len(packet) - association.icvLength
		if body < espHeaderLength+2*aes.BlockSize || (body-espHeaderLength)%aes.BlockSize != 0 {
			return 0, nil, 0, errors.New("ESP packet has a bad length")
		}
		if !hmac.Equal(association.icv(packet[:body]), packet[body:]) {
			return 0, nil, 0, errAuthentication
		}
		iv := packet[espHeaderLength : espHeaderLength+aes.BlockSize]
		plaintext = make([]byte, body-espHeaderLength-aes.BlockSize)
		cipher.NewCBCDecrypter(association.block, iv).CryptBlocks(plaintext, packet[espHeaderLength+aes.BlockSize:body])
	}

	if len(plaintext) < 2 {
		return 0, nil, 0, errors.New("ESP packet has no trailer")
	}
	padding := int(plaintext[len(plaintext)-2])
	if padding+2 > len(plaintext) {
		return 0, nil, 0, errors.New("ESP packet has bad padding")
	}
	return sequence, plaintext[:len(plaintext)-2-padding], plaintext[len(plaintext)-1], nil
}

// replayWindow rejects sequence numbers it has seen, and those too old to tell (RFC 4303,
// section 3.4.3).
type replayWindow struct {
	top    uint32
	bitmap uint64
}

func (window *replayWindow) fresh(sequence uint32) bool {
	switch {
	case sequence == 0:
		return false
	case sequence > window.top:
		return true
	case window.top-sequence >= 64:
		return false
	}
	return window.bitmap&(1<<(window.top-sequence)) == 0
}

// accept records sequence once its packet passed authentication.
func (window *replayWindow) accept(sequence uint32) {
	if sequence > window.top {
		if shift := sequence - window.top; shift < 64 {
			window.bitmap <<= shift
		} else {
			window.bitmap = 0
		}
		window.top = sequence
	}
	window.bitmap |= 1 << (window.top - sequence)
}
