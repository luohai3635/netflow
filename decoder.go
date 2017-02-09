package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tehmaze/netflow/netflow5"

	"github.com/tehmaze/netflow/netflow9"
	"github.com/tehmaze/netflow/session"
)

// Decoder for NetFlow messages.
type Decoder struct {
	session.Session
}

// Message generlized interface.
type Message interface {
}

// NewDecoder sets up a decoder suitable for reading NetFlow packets.
func NewDecoder(s session.Session) *Decoder {
	return &Decoder{s}
}

// Read a single Netflow message from the network. If an error is returned,
// there is no guarantee the following reads will be succesful.
func (d *Decoder) Read(r io.Reader) (Message, error) {
	data := [2]byte{}
	if _, err := r.Read(data[:]); err != nil {
		return nil, err
	}

	version := binary.BigEndian.Uint16(data[:])
	buffer := bytes.NewBuffer(data[:])
	mr := io.MultiReader(buffer, r)

	switch version {

	case netflow5.Version:
		return netflow5.Read(mr)

	case netflow9.Version:
		return netflow9.Read(mr, d.Session, nil)

	default:
		return nil, fmt.Errorf("netflow: unsupported version %d", version)
	}
}
