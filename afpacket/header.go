// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package afpacket

import "C"
import (
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	VlanHlen        = 4
	EthAlen         = 6
	StatusVlanValid = 0x10
	sizeofV1Hdr     = unsafe.Sizeof(V1header{})
	sizeofV2Hdr     = unsafe.Sizeof(V2header{})
	sizeofV3Hdr     = unsafe.Sizeof(V3header{})
)

// Our model of handling all TPacket versions is a little hacky, to say the
// least.  We use the header interface to handle interactions with the
// tpacket1/tpacket2 packet header AND the tpacket3 block header.  The big
// difference is that tpacket3's block header implements the next() call to get
// the next packet within the block, while v1/v2 just always return false.

type header interface {
	// getStatus returns the TPacket status of the current header.
	getStatus() int
	// clearStatus clears the status of the current header, releasing its
	// underlying data back to the kernel for future use with new packets.
	// Using the header after calling clearStatus is an error.  clearStatus
	// should only be called after next() returns false.
	clearStatus()
	// getTime returns the timestamp for the current packet pointed to by
	// the header.
	getTime() time.Time
	// getData returns the packet data pointed to by the current header.
	getData(opts *options) []byte
	// getLength returns the total length of the packet.
	getLength() int
	// getIfaceIndex returns the index of the network interface
	// where the packet was seen. The index can later be translated to a name.
	getIfaceIndex() int
	// getVLAN returns the VLAN of a packet if it was provided out-of-band
	getVLAN() int
	// next moves this header to point to the next packet it contains,
	// returning true on success (in which case getTime and getData will
	// return values for the new packet) or false if there are no more
	// packets (in which case clearStatus should be called).
	next() bool
}

const tpacketAlignment = uint(unix.TPACKET_ALIGNMENT)

func tpAlign(x int) int {
	return int((uint(x) + tpacketAlignment - 1) &^ (tpacketAlignment - 1))
}

type V1header struct {
	Status  uint64
	Len     uint32
	Snaplen uint32
	Mac     uint16
	Net     uint16
	Sec     uint32
	Usec    uint32
	Padding [4]byte
}
type V2header struct {
	Status   uint32
	Len      uint32
	Snaplen  uint32
	Mac      uint16
	Net      uint16
	Sec      uint32
	Nsec     uint32
	VlanTci  uint16
	VlanTpid uint16
	Padding  [4]byte
}

func makeSlice(start uintptr, length int) (data []byte) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}

func insertVlanHeader(data []byte, vlanTCI int, opts *options) []byte {
	if vlanTCI == 0 || !opts.addVLANHeader {
		return data
	}
	eth := make([]byte, 0, len(data)+VlanHlen)
	eth = append(eth, data[0:EthAlen*2]...)
	eth = append(eth, []byte{0x81, 0, byte((vlanTCI >> 8) & 0xff), byte(vlanTCI & 0xff)}...)
	return append(eth, data[EthAlen*2:]...)
}

func (h *V1header) getVLAN() int {
	return -1
}
func (h *V1header) getStatus() int {
	return int(h.Status)
}
func (h *V1header) clearStatus() {
	h.Status = 0
}
func (h *V1header) getTime() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Usec)*1000)
}
func (h *V1header) getData(opts *options) []byte {
	return makeSlice(uintptr(unsafe.Pointer(h))+uintptr(h.Mac), int(h.Snaplen))
}
func (h *V1header) getLength() int {
	return int(h.Len)
}
func (h *V1header) getIfaceIndex() int {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(int(sizeofV1Hdr)))))
	return int(ll.Ifindex)
}
func (h *V1header) next() bool {
	return false
}

func (h *V2header) getVLAN() int {
	return -1
}
func (h *V2header) getStatus() int {
	return int(h.Status)
}
func (h *V2header) clearStatus() {
	h.Status = 0
}
func (h *V2header) getTime() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Nsec))
}
func (h *V2header) getData(opts *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(h))+uintptr(h.Mac), int(h.Snaplen))
	return insertVlanHeader(data, int(h.VlanTci), opts)
}
func (h *V2header) getLength() int {
	return int(h.Len)
}
func (h *V2header) getIfaceIndex() int {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(int(sizeofV2Hdr)))))
	return int(ll.Ifindex)
}
func (h *V2header) next() bool {
	return false
}

type TpacketHdrVariant1 struct {
	TpRxhash   uint32
	TpVlanTci  uint32
	TpVlanTpid uint16
	Padding    uint16
}

type TpPacketBdTs struct {
	Sec  uint32
	Usec uint32
}

type TpPacket struct {
	TpNextOffset uint32
	Tp_sec       uint32
	Tp_nsec      uint32
	Tp_snaplen   uint32
	Tp_len       uint32
	Tp_status    uint32
	Tp_mac       uint16
	Tp_net       uint16
	Tp_hv1       TpacketHdrVariant1
	Padding      [8]uint8
}

type TpBlock struct {
	Version uint32
	ToPriv  uint32
	Hdr     [40]byte
}

type V3header struct {
	Block    *TpBlock
	Blockhdr *TpacketHdrV1
	Packet   *TpPacket
	used     uint32
}

type SockAddrLL struct {
	Family   uint16
	Protocol uint16
	Ifindex  int32
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
}

type TpacketHdrV1 struct {
	BlockStatus      uint32
	NumPkts          uint32
	OffsetToFirstPkt uint32
	BlkLen           uint32
	SeqNum           uint64
	TsFirstPkt       TpPacketBdTs
	TsLastPkt        TpPacketBdTs
}

func initV3Wrapper(block unsafe.Pointer) (w V3header) {
	w.Block = (*TpBlock)(block)
	w.Blockhdr = (*TpacketHdrV1)(unsafe.Pointer(&w.Block.Hdr[0]))
	w.Packet = (*TpPacket)(unsafe.Pointer(uintptr(block) + uintptr(w.Blockhdr.OffsetToFirstPkt)))
	return
}

func (w *V3header) getVLAN() int {
	if w.Packet.Tp_status&StatusVlanValid != 0 {
		//hv1 := (*TpacketHdrVariant1)(unsafe.Pointer(&w.TpPacket.anon0[0]))
		return int(w.Packet.Tp_hv1.TpVlanTci & 0xfff)
	}
	return -1
}

func (w *V3header) getStatus() int {
	return int(w.Blockhdr.BlockStatus)
}
func (w *V3header) clearStatus() {
	w.Blockhdr.BlockStatus = 0
}
func (w *V3header) getTime() time.Time {
	return time.Unix(int64(w.Packet.Tp_sec), int64(w.Packet.Tp_nsec))
}
func (w *V3header) getData(opts *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(w.Packet))+uintptr(w.Packet.Tp_mac), int(w.Packet.Tp_snaplen))

	//hv1 := (*C.struct_tpacket_hdr_variant1)(unsafe.Pointer(&w.TpPacket.anon0[0]))
	return insertVlanHeader(data, int(w.Packet.Tp_hv1.TpVlanTci), opts)
}
func (w *V3header) getLength() int {
	return int(w.Packet.Tp_len)
}

func (w *V3header) getIfaceIndex() int {
	ll := (*SockAddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(w.Packet)) + uintptr(tpAlign(int(sizeofV3Hdr)))))
	return int(ll.Ifindex)
}
func (w *V3header) next() bool {
	w.used++
	if w.used >= w.Blockhdr.NumPkts {
		return false
	}

	next := uintptr(unsafe.Pointer(w.Packet))
	if w.Packet.TpNextOffset != 0 {
		next += uintptr(w.Packet.TpNextOffset)
	} else {
		next += uintptr(tpAlign(int(w.Packet.Tp_snaplen) + int(w.Packet.Tp_mac)))
	}
	w.Packet = (*TpPacket)(unsafe.Pointer(next))
	return true
}
