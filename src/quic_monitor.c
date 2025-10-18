#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// bcc/proto.h include structure for ethernet, ip, and udp packets


//structure used to monitor quic connection
struct q_key_t {
    u32 src_ip;
    u32 dst_ip;
};

struct q_stats_t {
    u64 pkt_count;
    // u64 conn_count;
    u64 malformed_count;
    u64 handshake_count;
};

BPF_HASH(quic_stats, struct q_key_t, struct q_stats_t);

//the Destination Connection ID is chosen by the recipient of the packet and is used to provide consistent routing; 
//the Source Connection ID is used to set the Destination Connection ID used by the peer.
//since the scid is static, only the dcid is needed to identify the connection
// BPF_MAP_TYPE_ARRAY(conn_stats, u64 dcid);

struct summary_t {
    u32 src_ip;
    u32 dst_ip;
    u64 pkt_count;
    // u64 conn_count;
    u64 malformed_count;
    u64 handshake_count;
};

//output to a ring buffer "events" of size 8 pages or 32 KB
BPF_RINGBUF_OUTPUT(events, 8);

//we parse the QUIC header for packet type and connection ids
static inline int parse_quic_header(void *cursor, void *data_end, u64 *dcid, u64 *scid, u8 *pkt_type) {
    // cursor points to QUIC payload (after UDP header)
    // QUIC header minimum is 18 bytes: 1 type + 8 dcid + 8 scid + 1 (optional byte)
    
    u8 *hdr = cursor;

    // ensure the header fits within packet bounds
    if ((void *)(hdr + 18) > data_end)
        return 1;  // malformed, truncated

    // first byte: packet type
    *pkt_type = hdr[0];

    // next 8 bytes: DCID (bytes 1–8)
    __builtin_memcpy(dcid, &hdr[1], sizeof(*dcid));

    // next 8 bytes: SCID (bytes 9–16)
    __builtin_memcpy(scid, &hdr[9], sizeof(*scid));

    // success
    return 0;
}


#define IP_UDP 17
#define UDP_HLEN 8
#define ETH_HLEN 14

int monitor_quic(struct __sk_buff *skb) {
	
	// we read the header using a pointer to determine if the packet is a QUIC packet
    u8 *cursor = 0;
	void *data_end = (void *)(long)skb->data_end;
	
	// cast the data starting from cursor into the ethernet_t struct from bcc/proto.h
	// advance the cursor by the size of the ethernet_t struct
	// and ensure bounds checking against data_end
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    // filter IP packets using the data (ethernet type = 0x0800)
    if (!(ethernet->type == 0x0800)) {
        return 0;
    }
	
	// similarly cast the data into a ip_t struct and advance the cursor by the size of the header
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    // filter UDP packets using the next protocol (ip next protocol = 17 or 0x11)
    if (ip->nextp != IP_UDP) {
        return 0;
    }
	
	// get the header length for the ip header. ip_t is the IPV4 struct
    u32 ip_header_length = ip->hlen << 2;  // multiply by 4 by shifting 2 bits to the left. hlen is in bits, convert to bytes
    
	// check header length against minimum size of an IPV4 header
	if (ip_header_length < sizeof(*ip)) {
        return 0;
    }

    // shift cursor forward for dynamic IP header size
	// skipping extra bytes if header lenght is larger than 20
    void *_ = cursor_advance(cursor, (ip_header_length - sizeof(*ip)));
	
	//cast to UDP header adn advance cursor
    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
	
	//get the length of the udp packet
	u32 udp_length = udp->length;
	
	//check to see if the udp lenght is smaller than the minimum
	if (udp_length < sizeof(*udp)) {
		return 0;
	}
    
	// filter QUIC by UDP port 443
    if (udp->sport != 443 && udp->dport != 443) {
       return 0;
    }

	u64 dcid = 0, scid = 0;
    u8 pkt_type = 0;
	
	// call parse_quic_header() here
	// the cursor is currently pointing to the QUIC header
	bool malformed_header = parse_quic_header(cursor, data_end, &dcid, &scid, &pkt_type);
	
	struct q_key_t key;
	key.src_ip = ip->src;
	key.dst_ip = ip->dst;
	
	struct q_stats_t init_stats = {0};
	struct q_stats_t *lookup_stats = quic_stats.lookup_or_try_init(&key, &init_stats);
	
	lookup_stats->pkt_count++;
	
	// if parse_quic_header return a -1
	// increment the malformed header count and packet count
	if (malformed_header) {
		lookup_stats->malformed_count++;
		goto COMMIT;
	}
	
	// detect if the packet is an initial handshake (QUIC Initial packet type = 0xC0 or 0xC1 depending on version)
	// and then increment the count
	if ((pkt_type & 0xF0) == 0xC0) {
        lookup_stats->handshake_count++;
	}
	
	// count the number of unique connections ids
	// by inserting them into an array an then using lookup()
	// if (!conn_stats.lookup(&dcid)) {
		// lookup_stats->conn_count++;
	// }
	
	goto COMMIT;
	
	
    //push summarized data every N packets to reduce performance overhead
	//using the 0xF mask (logical AND) to get the last 4 bits of the count, 
	//if the last 4 bits all equal to 0 => a cycle of 16 packets have been counted
	
	COMMIT:
    if ((lookup_stats->pkt_count & 0xF) == 0) {
		
        //create a summary of the last N packets for the connection
		struct summary_t summary = {
            .src_ip = key.src_ip,
            .dst_ip = key.dst_ip,
            .pkt_count = lookup_stats->pkt_count,
            // .conn_count = lookup_stats->conn_count,
            .malformed_count = lookup_stats->malformed_count,
            .handshake_count = lookup_stats->handshake_count,
        };
		
		//flush the data for the connection
		//quic_stats.clear();
		//conn_stats.clear();
		
		//push the summary to the ring buffer "events"
		//the bpf_ringbuf_output function
		//Copy size bytes from data into a ring buffer "ringbuf"
		//the summary will have the expected size of 40 * N bytes
        events.ringbuf_output(&summary, sizeof(summary), 0);
    }
	
	//exit the program
    return 0;
}
