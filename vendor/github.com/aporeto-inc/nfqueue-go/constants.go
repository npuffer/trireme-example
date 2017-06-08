package nfqueue

import (
	"syscall"
	"unsafe"
)

const (
	//NfDefaultPacketSize   the maximum size packet to expect on queue
	NfDefaultPacketSize = 0xffff
	//NFQUEUESUBSYSID The netlink subsystem id for nfqueue
	NFQUEUESUBSYSID = 0x3
	//SOCKFAMILY  constant for AF_NETLINK
	SOCKFAMILY = syscall.AF_NETLINK
	//SolNetlink  costant for SOL_NETLINK
	SolNetlink = 270 /* syscall.SOL_NETLINK not defined */

	//NFQNL - Netfilter Queue Netink message types

	//NfqnlMsgPacket  packet from kernel to userspace
	NfqnlMsgPacket msgTypes = 0x0
	//NfqnlMsgVerdict verdict from userspace to kernel
	NfqnlMsgVerdict msgTypes = 0x1
	//NfqnlMsgConfig connect to a particular queue
	NfqnlMsgConfig msgTypes = 0x2
	//NfqnlMsgVerdictBatch batch verdict from userspace to kernel
	NfqnlMsgVerdictBatch msgTypes = 0x3
	//unexported max
	//nfqnlMsgMax msgTypes = 0x4 //nodeadcode

	//NFQNL_ATTR = Netfilter Queue Netink atttributes

	//NfqaUnspec  unspecified
	NfqaUnspec nfqaAttr = 0x0
	//NfqaPacketHdr  Attr header for Packet payload
	NfqaPacketHdr nfqaAttr = 0x1
	//NfqaVerdictHdr  Attr header for verdict payload
	NfqaVerdictHdr uint16 = 0x2 /* nfqnlmsg_verdict_hrd */
	//NfqaMark  Attr Header for Mark Payload
	NfqaMark nfqaAttr = 0x3 /* u_int32_t nfmark */
	//NfqaTimestamp  header for timestamp payload
	NfqaTimestamp nfqaAttr = 0x4 /* nfqnl_msg_packet_timestamp */
	//NfqaIfindexIndev -- Ifindex for in device payload
	NfqaIfindexIndev nfqaAttr = 0x5 /* u_int32_t ifindex */
	//NfqaIfindexOutdev -- Ifindex for out device payload
	NfqaIfindexOutdev nfqaAttr = 0x6 /* u_int32_t ifindex */
	//NfqaIfindexPhysindev -- Physical Device
	NfqaIfindexPhysindev nfqaAttr = 0x7 /* u_int32_t ifindex */
	//NfqaIfindexPhysoutdev -- Physical Device
	NfqaIfindexPhysoutdev nfqaAttr = 0x8 /* u_int32_t ifindex */
	//NfqaHwaddr -- Hardware Address
	NfqaHwaddr nfqaAttr = 0x9 /* nfqnl_msg_packet_hw */
	//NfqaPayload -- Packet Payload
	NfqaPayload nfqaAttr = 0xa /* opaque data payload */
	//unexported max
	nfqaMax nfqaAttr = 0xb

	//NfqnlCfgCmdnone -- None
	NfqnlCfgCmdnone nfqConfigCommands = 0x0
	//NfqnlCfgCmdBind -- queue bind command
	NfqnlCfgCmdBind nfqConfigCommands = 0x1
	//NfqnlCfgCmdUnbind -- queue unbind command
	NfqnlCfgCmdUnbind nfqConfigCommands = 0x2
	//NfqnlCfgCmdPfBind -- bind family
	NfqnlCfgCmdPfBind nfqConfigCommands = 0x3
	//NfqnlCfgCmdPfUnbind -- unbind family
	NfqnlCfgCmdPfUnbind nfqConfigCommands = 0x4

	//NfqnlCopyNone -- Copy no packet bytes to userspace
	NfqnlCopyNone nfqConfigMode = 0x0
	//NfqnlCopyMeta -- Copy only metadata
	NfqnlCopyMeta nfqConfigMode = 0x1
	//NfqnlCopyPacket -- Copy packet bytes specified by Range
	NfqnlCopyPacket nfqConfigMode = 0x2

	/* Flags values */
	/* from netlink.h*/

	/*NlmFRequest -- It is request message. 	*/
	NlmFRequest NlmFlags = 0x1
	/*NlmFMulti -- Multipart message, terminated by NlMsgDone */
	NlmFMulti NlmFlags = 0x2
	/*NlmFAck -- Reply with ack, with zero or error code */
	NlmFAck NlmFlags = 0x4
	/*NlmFEcho -- Echo this request 		*/
	NlmFEcho NlmFlags = 0x8
	/*NlmFDumpintr --  Dump was inconsistent due to sequence change */
	NlmFDumpintr NlmFlags = 0x10
	/*NlmFDumpFiltered -- Dump was filtered as requested */
	NlmFDumpFiltered NlmFlags = 0x20

	//NfnlBuffSize -- Buffer size of socket
	NfnlBuffSize uint32 = 65535
	//NFNetlinkV0 - netlink v0
	NFNetlinkV0 uint8 = 0
	//SizeofMsgConfigCommand -- Sizeof config command struct
	SizeofMsgConfigCommand = 0x4
	//SizeofNfGenMsg -- Sizeof nfgen msg struct
	SizeofNfGenMsg uint32 = 0x4
	//SizeofNfAttr -- Sizeof nfattr struct
	// This does not account for the size of the byte slice at the end
	SizeofNfAttr uint16 = 0x4
	//SizeOfNfqMsgConfigParams -- Sizeof NfqMsgConfigParams
	SizeOfNfqMsgConfigParams uint32 = uint32(unsafe.Sizeof(NfqMsgConfigParams{}))
	//SizeOfNfqMsgConfigQueueLen -- Sizeof NfqMsgConfigQueueLen
	SizeOfNfqMsgConfigQueueLen uint32 = uint32(unsafe.Sizeof(NfqMsgConfigQueueLen{}))
	//SizeofNfqMsgVerdictHdr -- Sizeof verdict hdr struct
	SizeofNfqMsgVerdictHdr uint32 = 0x8
	//SizeofNfqMsgMarkHdr -- sizeof mark hdr
	SizeofNfqMsgMarkHdr = 0x4
	//APUNSPEC -- PF_UNSPEC/AF_UNSPEC
	APUNSPEC uint8 = syscall.AF_UNSPEC

	//NfqaCfgUnspec -- Unspec
	NfqaCfgUnspec uint32 = 0x0
	//NfqaCfgCmd -- attr config command
	NfqaCfgCmd uint16 = 0x1 /* nfqnl_msg_config_cmd */
	//NfqaCfgParams -- config parameters
	NfqaCfgParams uint16 = 0x2 /* nfqnl_msg_config_params */
	//NfqaCfgQueueMaxLen -- MaxQueuelen
	NfqaCfgQueueMaxLen uint16 = 0x3 /* u_int32_t */
	//NfqaCfgMask -- Mask
	NfqaCfgMask uint32 = 0x4 /* identify which flags to change */
	//NfqaCfgFlags -- Config Flags
	NfqaCfgFlags uint32 = 0x5 /* value of these flags (__u32) */
	//nfqaCfgMax -- unexported max
	//nfqaCfgMax uint32 = 0x6 //nodeadcode

	//NlMsgNoop -- do nothing
	NlMsgNoop = 0x1 /* nothing.		*/
	//NlMsgError -- error message from netlink
	NlMsgError = 0x2 /* error		*/
	//NlMsgDone -- Multi part message done
	NlMsgDone = 0x3 /* end of a dump	*/
	//NlMsgOverrun -- Overrun of buffer
	NlMsgOverrun = 0x4 /* data lost		*/
	//unexported type
	//nlmsgMinType = 0x10 //nodeadcode /* < 0x10: reserved control messages */
)
