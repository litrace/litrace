package trace

import (
	"bytes"
	"encoding/binary"
)

type Event struct {
	Ts          uint64
	Dur         uint64
	SyscallID   int64
	Ret         int64
	Args        [6]uint64
	VarDesc     [6]VarArgDesc
	Payload     [512]byte
	Pid         uint32
	Tid         uint32
	Seq         uint32
	PayloadLen  uint16
	ArgCount    uint8
	VarCount    uint8
	ArgTypes    [6]uint8
	VarReserved uint8
}

type VarArgDesc struct {
	ArgIndex uint8
	Flags    uint8
	Offset   uint16
	Length   uint16
	Reserved uint16
}

type event = Event
type varArgDesc = VarArgDesc

func DecodeEvent(raw []byte) (Event, error) {
	var ev Event
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return Event{}, err
	}
	return ev, nil
}
