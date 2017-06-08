package nfqueue

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	nlMsgAlignTo = 4 //Align to nibble boundaries
	nfaAlignTo   = 4
)

//NlMsgType Returns the Messagetype
func NlMsgType(h *syscall.NlMsghdr) uint16 {
	return h.Type & 0x00ff
}

//NlMsgSubsysID returns the subsystem id -- 3 for queue
func NlMsgSubsysID(h *syscall.NlMsghdr) uint16 {
	return (h.Type & 0xff00) >> 8
}

//NlMsgAlign -- Align to 4 byte boundary
func NlMsgAlign(len uint32) uint32 {
	return (len + nlMsgAlignTo - 1) &^ (nlMsgAlignTo - 1)
}

//NfaAlign -- Align to 4 byte boundary
func NfaAlign(len uint16) uint16 {
	return (len + nfaAlignTo - 1) &^ (nfaAlignTo - 1)
}

//NlMsgLength -- adjust length to end on 4 byte multiple
func NlMsgLength(len uint32) uint32 {
	return len + NlMsgAlign(syscall.SizeofNlMsghdr)
}

//NlMsgSpace -- Space required to hold this message
func NlMsgSpace(len uint32) uint32 {
	return NlMsgAlign(NlMsgLength(len))
}

//NfaLength -- adjust length to end on 4 byte multiple
func NfaLength(len uint16) uint16 {
	return NfaAlign(len + SizeofNfAttr)
}

//BuildNlMsgHeader -- Build syscall.NlMsgHdr structure
//msgType: The message type to be send | SUBSYSID - 3 for us
//Len: Len of the payload including the sizeof nlmsghdr
//msgFlags: Request Flags
func BuildNlMsgHeader(msgType msgTypes, msgFlags NlmFlags, len uint32) *syscall.NlMsghdr {
	return &syscall.NlMsghdr{
		Len:   NlMsgLength(len),
		Type:  (NFQUEUESUBSYSID << 8) | uint16(msgType),
		Flags: uint16(msgFlags),
		Pid:   0,
		Seq:   0,
	}

}

//BuildNfgenMsg -- Build nfgen msg strcuure
//family -- SOCK FAMILY
//Version -- Version
//resId -- queuenum
//n - syscall.NlMsghdr to adjust length after adding nfgen
func BuildNfgenMsg(family uint8, version uint8, resID uint16, n *syscall.NlMsghdr) *NfqGenMsg {
	n.Len = NlMsgLength(SizeofNfGenMsg)
	return &NfqGenMsg{
		nfgenFamily: family,
		version:     version,
		resID:       resID,
	}
}

//BuildNfAttrMsg -- Build nfattr message
//length -- length of the attr payload -- unused
//attrType -- Type of attr being added
//data --- The actual data being added. We only use this to figure out the size of payload.
//The payload needs to be appended separately
//n -- syscall.NlMsgHdr adjust length after building the nfattr
func BuildNfAttrMsg(length uint16, attrType uint16, n *syscall.NlMsghdr, dataLen uint32) *NfAttr {
	attr := &NfAttr{}
	attr.nfaType = attrType
	attr.nfaLen = NfaLength(uint16((dataLen)))
	n.Len += uint32(NfaLength(uint16((dataLen))))
	return attr
}

//SerializeNlMsgHdr -- Serialize syscall.NlMsgHdr to byte slice
func SerializeNlMsgHdr(hdr *syscall.NlMsghdr) []byte {
	buf := make([]byte, syscall.SizeofNlMsghdr)
	native.PutUint32(buf[0:4], hdr.Len)
	native.PutUint16(buf[4:6], hdr.Type)
	native.PutUint16(buf[6:8], hdr.Flags)
	native.PutUint32(buf[8:12], hdr.Seq)
	native.PutUint32(buf[12:16], hdr.Pid)
	return buf
}

//SerializeNlMsgHdrBuf -- Serialize into passed buffer and returns number of bytes copied
func SerializeNlMsgHdrBuf(hdr *syscall.NlMsghdr, buf []byte) int {
	native.PutUint32(buf[0:4], hdr.Len)
	native.PutUint16(buf[4:6], hdr.Type)
	native.PutUint16(buf[6:8], hdr.Flags)
	native.PutUint32(buf[8:12], hdr.Seq)
	native.PutUint32(buf[12:16], hdr.Pid)
	return syscall.SizeofNlMsghdr
}

//GetPacketInfo -- Extract packet info from netlink response
//Returns mark,packetid and packet payload
//Mark is uint32
func GetPacketInfo(attr []*NfAttrResponsePayload) (int, int, []byte) {
	var packetID, mark int

	if attr[NfqaPacketHdr] != nil {
		packetID = int(native.Uint32(attr[int(NfqaPacketHdr)].data))
	}
	if attr[NfqaMark] != nil {
		mark = int(binary.BigEndian.Uint32(attr[int(NfqaMark)].data))
	}
	if attr[NfqaPayload] != nil {
		return packetID, mark, attr[NfqaPayload].data
	}
	return packetID, mark, []byte{}
}

//ToWireFormat -- Convert NfqMsgVerdictHdr to byte slice
func (r *NfqMsgVerdictHdr) ToWireFormat() []byte {
	buf := make([]byte, SizeofNfqMsgVerdictHdr)
	binary.BigEndian.PutUint32(buf, r.verdict)
	native.PutUint32(buf[4:], r.id)
	return buf
}

//ToWireFormatBuf -- Convert structure to []byte and copy the []byte to passed buffer
func (r *NfqMsgVerdictHdr) ToWireFormatBuf(buf []byte) int {
	binary.BigEndian.PutUint32(buf, r.verdict)
	native.PutUint32(buf[4:], r.id)
	return int(r.Length())
}

//Length  -- return length of struct
func (r *NfqMsgVerdictHdr) Length() uint32 {
	return SizeofNfqMsgVerdictHdr
}

//ToWireFormat -- Convert NfqGenMsg to byte slice
func (r *NfqGenMsg) ToWireFormat() []byte {
	buf := make([]byte, SizeofNfGenMsg)
	copy(buf, []byte{r.nfgenFamily})
	copy(buf[1:], []byte{r.version})
	//The queue needs to store in network order
	binary.BigEndian.PutUint16(buf[2:], r.resID)
	return buf
}

//ToWireFormatBuf -- Convert struct to []byte and copy it to passed buffer
func (r *NfqGenMsg) ToWireFormatBuf(buf []byte) int {
	copy(buf, []byte{r.nfgenFamily})
	copy(buf[1:], []byte{r.version})
	//The queue needs to store in network order
	binary.BigEndian.PutUint16(buf[2:], r.resID)
	return int(r.Length())
}

//Length  -- Return length of struct
func (r *NfqGenMsg) Length() uint32 {
	return SizeofNfGenMsg
}

//ToWireFormat -- Convert  NfqMsgMarkHdr to byte slice
func (r *NfqMsgMarkHdr) ToWireFormat() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, r.mark)
	return buf
}

//ToWireFormatBuf -- Convert struct to []byte and copy it passed buf
func (r *NfqMsgMarkHdr) ToWireFormatBuf(buf []byte) int {
	binary.BigEndian.PutUint32(buf, r.mark)
	return int(r.Length())
}

//Length -- Return length of struct
func (r *NfqMsgMarkHdr) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgMarkHdr{}))
}

//ToWireFormat -- Convert NfqMsgConfigCommand to byte slice
func (r *NfqMsgConfigCommand) ToWireFormat() []byte {

	buf := make([]byte, SizeofMsgConfigCommand)
	buf[0] = byte(r.Command)
	buf[1] = r._pad
	binary.LittleEndian.PutUint16(buf[2:], r.pf)
	return buf
}

//Length -- Return length of struct
func (r *NfqMsgConfigCommand) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgConfigCommand{}))
}

//ToWireFormat -- Convert NfAttr to byte slice
func (r *NfAttr) ToWireFormat() []byte {
	buf := make([]byte, int(SizeofNfAttr))
	native.PutUint16(buf, r.nfaLen)
	native.PutUint16(buf[2:], r.nfaType)
	return buf
}

//ToWireFormatBuf -- Convert struct to []byte and copy it to passed buffer
func (r *NfAttr) ToWireFormatBuf(buf []byte) int {
	native.PutUint16(buf, r.nfaLen)
	native.PutUint16(buf[2:], r.nfaType)
	return int(r.Length())
}

//Length -- Return length of struct
func (r *NfAttr) Length() uint32 {
	return uint32(unsafe.Sizeof(NfAttr{}))
}

//ToWireFormat -- Convert NfqMsgConfigParams to byte slice
func (r *NfqMsgConfigParams) ToWireFormat() []byte {
	buf := make([]byte, SizeOfNfqMsgConfigParams)
	binary.BigEndian.PutUint32(buf, r.copyRange)
	buf[4] = byte(r.copyMode)
	return buf
}

//Length -- Return length of struct
func (r *NfqMsgConfigParams) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgConfigParams{}))
}

//ToWireFormat -- Convert NfqMsgConfigQueueLen to byte slice
func (r *NfqMsgConfigQueueLen) ToWireFormat() []byte {
	buf := make([]byte, SizeOfNfqMsgConfigQueueLen)
	binary.BigEndian.PutUint32(buf, r.queueLen)
	return buf
}

//Length -- Return length of struct
func (r *NfqMsgConfigQueueLen) Length() uint32 {
	return uint32(unsafe.Sizeof(NfqMsgConfigQueueLen{}))
}

//NetlinkMessageToStruct -- Convert netlink message byte slice to struct and payload
func NetlinkMessageToStruct(buf []byte) (*syscall.NlMsghdr, []byte, error) {
	hdr := &syscall.NlMsghdr{}
	hdr.Len = native.Uint32(buf)
	hdr.Type = native.Uint16(buf[4:])
	hdr.Flags = native.Uint16(buf[6:])
	hdr.Seq = native.Uint32(buf[8:])
	hdr.Pid = native.Uint32(buf[12:])

	return hdr, buf[16:], nil
}

//NetlinkMessageToNfGenStruct -- Convert netlink byte slice to nfqgen msg structure
func NetlinkMessageToNfGenStruct(buf []byte) (*NfqGenMsg, []byte, error) {
	hdr := &NfqGenMsg{}
	hdr.nfgenFamily = buf[0]
	hdr.version = buf[1]
	hdr.resID = binary.BigEndian.Uint16(buf[2:])
	return hdr, buf[4:], nil
}

//NetlinkMessageToNfAttrStruct -- Convert byte slice representing nfattr to nfattr struct slice
func NetlinkMessageToNfAttrStruct(buf []byte, hdr []*NfAttrResponsePayload) ([]*NfAttrResponsePayload, []byte, error) {
	i := 0
	for i < len(buf) {
		if i+4 >= len(buf) {
			break
		}
		nfaLen := native.Uint16(buf[i:])
		nfaType := native.Uint16(buf[i+2:])
		i = i + 4
		if i+int(nfaLen)+4 > len(buf) {
			return nil, nil, fmt.Errorf("Invalid packet %v", hex.Dump(buf))
		}
		if nfaType < uint16(nfqaMax) {
			if i+int(nfaLen)-4 >= len(buf) {
				break
			}
			hdr[nfaType] = &NfAttrResponsePayload{
				data: buf[i : i+int(nfaLen)-4],
			}
		}
		i = i + int(nfaLen) - 4
		i = int(NfaAlign(uint16(i)))
	}
	if i >= len(buf) {
		return hdr, nil, nil
	}
	return hdr, buf[i:], nil
}

//NetlinkErrMessagetoStruct -- parse byte slice and return syscall.NlMsgerr
func NetlinkErrMessagetoStruct(buf []byte) (*syscall.NlMsghdr, *syscall.NlMsgerr) {
	err := &syscall.NlMsgerr{}
	err.Error = int32(native.Uint32(buf))
	hdr, _, _ := NetlinkMessageToStruct(buf[4:])
	return hdr, err
}

//ParseNfAttrResponse -- Parse the Nfattrresponse payload
// func ParseNfAttrResponse(element *NfAttrResponsePayload) (uint16, uint16, []byte) {
//     return element.attr.nfaLen, element.attr.nfaType, element.data
// }

//QueueID -- return queueid
func QueueID(msg *NfqGenMsg) uint16 {
	return msg.resID
}
