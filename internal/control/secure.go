package control

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"gremlind/internal/auth"
)

const encryptedInfo = "gremlind control psk encryption v1"

type secureChannel struct {
	br       *bufio.Reader
	rw       io.Writer
	readKey  cipher.AEAD
	writeKey cipher.AEAD
	readSeq  uint64
	writeSeq uint64
}

func newClientSecureChannel(secret, clientID string, serverNonce, clientNonce auth.Nonce, br *bufio.Reader, rw io.Writer) (*secureChannel, error) {
	c2s, s2c, err := deriveChannelKeys(secret, clientID, serverNonce, clientNonce)
	if err != nil {
		return nil, err
	}
	return &secureChannel{br: br, rw: rw, readKey: s2c, writeKey: c2s}, nil
}

func newServerSecureChannel(secret, clientID string, serverNonce, clientNonce auth.Nonce, br *bufio.Reader, rw io.Writer) (*secureChannel, error) {
	c2s, s2c, err := deriveChannelKeys(secret, clientID, serverNonce, clientNonce)
	if err != nil {
		return nil, err
	}
	return &secureChannel{br: br, rw: rw, readKey: c2s, writeKey: s2c}, nil
}

func deriveChannelKeys(secret, clientID string, serverNonce, clientNonce auth.Nonce) (cipher.AEAD, cipher.AEAD, error) {
	salt := make([]byte, 0, auth.NonceLen*2+len(clientID))
	salt = append(salt, serverNonce[:]...)
	salt = append(salt, clientNonce[:]...)
	salt = append(salt, clientID...)
	prk := hkdfExtract(salt, []byte(secret))
	c2sKey := hkdfExpand(sha256.New, prk, []byte(encryptedInfo+" client-to-server"), 32)
	s2cKey := hkdfExpand(sha256.New, prk, []byte(encryptedInfo+" server-to-client"), 32)
	c2s, err := newGCM(c2sKey)
	if err != nil {
		return nil, nil, err
	}
	s2c, err := newGCM(s2cKey)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *secureChannel) WriteMessage(m Message) error {
	plain := marshalPlainFrame(m)
	nonce := seqNonce(c.writeSeq)
	ciphertext := c.writeKey.Seal(nil, nonce[:], plain, nil)
	c.writeSeq++
	return WriteMessage(c.rw, &Encrypted{Ciphertext: ciphertext})
}

func (c *secureChannel) ReadMessage() (Message, error) {
	outer, err := ReadMessage(c.br)
	if err != nil {
		return nil, err
	}
	env, ok := outer.(*Encrypted)
	if !ok {
		return nil, fmt.Errorf("control: expected encrypted frame, got type %d", outer.Type())
	}
	nonce := seqNonce(c.readSeq)
	plain, err := c.readKey.Open(nil, nonce[:], env.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("control: decrypt: %w", err)
	}
	c.readSeq++
	return unmarshalPlainFrame(plain)
}

func marshalPlainFrame(m Message) []byte {
	payload := m.marshalPayload()
	frame := make([]byte, frameHeaderLen, frameHeaderLen+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
	frame[2] = ProtoVersion
	frame[3] = byte(m.Type())
	frame = append(frame, payload...)
	return frame
}

func unmarshalPlainFrame(frame []byte) (Message, error) {
	if len(frame) < frameHeaderLen {
		return nil, io.ErrUnexpectedEOF
	}
	payloadLen := int(binary.BigEndian.Uint16(frame[0:2]))
	if frame[2] != ProtoVersion {
		return nil, fmt.Errorf("control: unsupported protocol version %d", frame[2])
	}
	if payloadLen != len(frame)-frameHeaderLen {
		return nil, fmt.Errorf("control: encrypted payload length mismatch")
	}
	msg := newMessage(MsgType(frame[3]))
	if msg == nil || msg.Type() == MsgEncrypted {
		return nil, fmt.Errorf("control: invalid encrypted message type %d", frame[3])
	}
	if err := msg.unmarshalPayload(frame[frameHeaderLen:]); err != nil {
		return nil, err
	}
	return msg, nil
}

func seqNonce(seq uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

func hkdfExtract(salt, secret []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

func hkdfExpand(hash func() hash.Hash, prk, info []byte, l int) []byte {
	var t []byte
	okm := make([]byte, 0, l)
	for counter := byte(1); len(okm) < l; counter++ {
		mac := hmac.New(hash, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:l]
}
