package afpacket

/*
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <linux/if_ether.h>  // ETH_P_ALL
#include <sys/socket.h>  // socket()
#include <unistd.h>  // close()
#include <arpa/inet.h>  // htons()
#include <sys/mman.h>  // mmap(), munmap()
#include <poll.h>  // poll()
#define VLAN_HLEN	4
*/
import "C"

var (
	tpV1HdrSize = C.sizeof_struct_tpacket_hdr
	tpV2HdrSize = C.sizeof_struct_tpacket2_hdr
	tpV3HdrSize = C.sizeof_struct_tpacket3_hdr
)

const (
	EtherHdrLen = C.ETH_ALEN
	VlanHdrLen  = C.VLAN_HLEN
)

type (
	Cint    C.int
	SockLen C.socklen_t

	TpReq   C.struct_tpacket_req
	TpV3Req C.struct_tpacket_req3

	SocketStats struct {
		StatsPackets uint32
		StatsDrops   uint32
	}

	SocketStatsV3 struct {
		SocketStats
		FreezeQueueCount uint32
	}

	Timestamp C.struct_tpacket_bd_ts

	TpV1Hdr C.struct_tpacket_hdr
	TpV2Hdr C.struct_tpacket2_hdr
	TpV3Hdr struct {
		block    *TpV3Block
		blockhdr *TpV3BlockHdr
		packet   *TpV3Packet
		used     TpV3Used
	}

	SockaddrLL = C.struct_sockaddr_ll
)
type (
	HeaderVariant1 C.struct_tpacket_hdr_variant1
	TpV3Block      C.struct_tpacket_block_desc
	TpV3BlockHdr   C.struct_tpacket_hdr_v1
	TpV3Packet     C.struct_tpacket3_hdr
	TpV3Used       C.__u32
)
