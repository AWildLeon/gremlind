package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"gremlind/internal/auth"
)

// Frame layout: [uint16 payloadLen][uint8 version][uint8 type][payload...].
const frameHeaderLen = 4

// MaxPayload bounds a single message payload (uint16 length field).
const MaxPayload = 0xffff

var errShortPayload = errors.New("control: truncated payload")

// WriteMessage encodes and writes a single framed message.
func WriteMessage(w io.Writer, m Message) error {
	payload := m.marshalPayload()
	if len(payload) > MaxPayload {
		return fmt.Errorf("control: payload too large (%d bytes)", len(payload))
	}
	frame := make([]byte, frameHeaderLen, frameHeaderLen+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
	frame[2] = ProtoVersion
	frame[3] = byte(m.Type())
	frame = append(frame, payload...)
	return writeFull(w, frame)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// ReadMessage reads and decodes a single framed message, allowing the full
// protocol maximum payload.
func ReadMessage(r *bufio.Reader) (Message, error) {
	return ReadMessageLimited(r, MaxPayload)
}

// ReadMessageLimited reads and decodes a single framed message, rejecting any
// frame whose declared payload exceeds maxPayload *before* allocating for it. It
// also rejects unknown protocol versions and message types. The limit bounds the
// memory an unauthenticated peer can pin during the handshake.
func ReadMessageLimited(r *bufio.Reader, maxPayload int) (Message, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	payloadLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	version := hdr[2]
	msgType := MsgType(hdr[3])
	if version != ProtoVersion {
		return nil, fmt.Errorf("control: unsupported protocol version %d", version)
	}
	if payloadLen > maxPayload {
		return nil, fmt.Errorf("control: payload %d exceeds limit %d", payloadLen, maxPayload)
	}
	msg := newMessage(msgType)
	if msg == nil {
		return nil, fmt.Errorf("control: unknown message type %d", msgType)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if err := msg.unmarshalPayload(payload); err != nil {
		return nil, err
	}
	return msg, nil
}

// --- field encoder ---

type enc struct{ b []byte }

func (e *enc) u8(v uint8)   { e.b = append(e.b, v) }
func (e *enc) u16(v uint16) { e.b = binary.BigEndian.AppendUint16(e.b, v) }
func (e *enc) u32(v uint32) { e.b = binary.BigEndian.AppendUint32(e.b, v) }

// str writes a uint16-length-prefixed string.
func (e *enc) str(s string) {
	e.u16(uint16(len(s)))
	e.b = append(e.b, s...)
}

// bytes writes a uint16-length-prefixed byte slice.
func (e *enc) bytes(p []byte) {
	e.u16(uint16(len(p)))
	e.b = append(e.b, p...)
}

// addr writes a netip.Addr as a single length byte (0/4/16) followed by bytes.
func (e *enc) addr(a netip.Addr) {
	if !a.IsValid() {
		e.u8(0)
		return
	}
	b, _ := a.MarshalBinary() // 4 or 16 bytes; never errors for valid Addr
	e.u8(uint8(len(b)))
	e.b = append(e.b, b...)
}

// --- field decoder ---

type dec struct {
	b   []byte
	pos int
	err error
}

func (d *dec) fail() bool {
	if d.err == nil {
		d.err = errShortPayload
	}
	return false
}

func (d *dec) need(n int) bool {
	if d.err != nil {
		return false
	}
	if d.pos+n > len(d.b) {
		return d.fail()
	}
	return true
}

func (d *dec) u8() uint8 {
	if !d.need(1) {
		return 0
	}
	v := d.b[d.pos]
	d.pos++
	return v
}

func (d *dec) u16() uint16 {
	if !d.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(d.b[d.pos:])
	d.pos += 2
	return v
}

func (d *dec) u32() uint32 {
	if !d.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(d.b[d.pos:])
	d.pos += 4
	return v
}

func (d *dec) str() string {
	n := int(d.u16())
	if !d.need(n) {
		return ""
	}
	s := string(d.b[d.pos : d.pos+n])
	d.pos += n
	return s
}

func (d *dec) bytes() []byte {
	n := int(d.u16())
	if !d.need(n) {
		return nil
	}
	if n == 0 {
		return nil
	}
	p := make([]byte, n)
	copy(p, d.b[d.pos:d.pos+n])
	d.pos += n
	return p
}

func (d *dec) addr() netip.Addr {
	n := int(d.u8())
	if n == 0 {
		return netip.Addr{}
	}
	if n != 4 && n != 16 {
		d.err = fmt.Errorf("control: invalid address length %d", n)
		return netip.Addr{}
	}
	if !d.need(n) {
		return netip.Addr{}
	}
	var a netip.Addr
	if err := a.UnmarshalBinary(d.b[d.pos : d.pos+n]); err != nil {
		d.err = err
		return netip.Addr{}
	}
	d.pos += n
	return a
}

// finish returns any decode error, or an error if trailing bytes remain.
func (d *dec) finish() error {
	if d.err != nil {
		return d.err
	}
	if d.pos != len(d.b) {
		return fmt.Errorf("control: %d trailing bytes", len(d.b)-d.pos)
	}
	return nil
}

// --- per-message payloads ---

func (m *Hello) marshalPayload() []byte {
	e := &enc{}
	e.str(m.ClientID)
	e.u32(m.Capabilities)
	return e.b
}

func (m *Hello) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.ClientID = d.str()
	m.Capabilities = d.u32()
	return d.finish()
}

func (m *Challenge) marshalPayload() []byte {
	e := &enc{}
	e.b = append(e.b, m.Nonce[:]...)
	return e.b
}

func (m *Challenge) unmarshalPayload(b []byte) error {
	if len(b) != auth.NonceLen {
		return fmt.Errorf("control: challenge nonce must be %d bytes, got %d", auth.NonceLen, len(b))
	}
	copy(m.Nonce[:], b)
	return nil
}

func (m *Auth) marshalPayload() []byte {
	e := &enc{}
	e.bytes(m.MAC)
	return e.b
}

func (m *Auth) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.MAC = d.bytes()
	return d.finish()
}

func (m *SessionRequest) marshalPayload() []byte {
	e := &enc{}
	e.u16(m.OuterMTU)
	e.addr(m.RequestedInner)
	return e.b
}

func (m *SessionRequest) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.OuterMTU = d.u16()
	m.RequestedInner = d.addr()
	return d.finish()
}

func (m *SessionReply) marshalPayload() []byte {
	e := &enc{}
	e.u8(uint8(m.Result))
	e.addr(m.ClientInner)
	e.addr(m.ServerInner)
	e.addr(m.ServerOuter)
	e.u32(m.GREKey)
	e.u16(m.MTU)
	e.str(m.Message)
	e.bytes(m.ServerMAC)
	return e.b
}

func (m *SessionReply) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.Result = Result(d.u8())
	m.ClientInner = d.addr()
	m.ServerInner = d.addr()
	m.ServerOuter = d.addr()
	m.GREKey = d.u32()
	m.MTU = d.u16()
	m.Message = d.str()
	m.ServerMAC = d.bytes()
	return d.finish()
}

// sessionReplyProofPayload returns the stable subset of a successful
// SessionReply covered by the server-authentication HMAC.
func sessionReplyProofPayload(m *SessionReply) []byte {
	e := &enc{}
	e.u8(uint8(m.Result))
	e.addr(m.ClientInner)
	e.addr(m.ServerInner)
	e.addr(m.ServerOuter)
	e.u32(m.GREKey)
	e.u16(m.MTU)
	return e.b
}

func (m *Echo) marshalPayload() []byte    { e := &enc{}; e.u32(m.Seq); return e.b }
func (m *EchoAck) marshalPayload() []byte { e := &enc{}; e.u32(m.Seq); return e.b }

func (m *Echo) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.Seq = d.u32()
	return d.finish()
}

func (m *EchoAck) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.Seq = d.u32()
	return d.finish()
}

func (m *Teardown) marshalPayload() []byte {
	e := &enc{}
	e.str(m.Reason)
	return e.b
}

func (m *Teardown) unmarshalPayload(b []byte) error {
	d := &dec{b: b}
	m.Reason = d.str()
	return d.finish()
}
