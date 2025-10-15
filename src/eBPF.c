#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/if_ether.h>
#include <bcc/proto.h>

//struct containing the source and destination pair of the QUIC packets
struct quic_key_t {
    u32 src_ip;
    u32 dst_ip;
};

//struct used to store the summarised statistics for the connection (per one source IP and destination IP pair)
//stores the number of packets sent between the two, the number of connection created, the number of malformed packets, and the number of handshake done
struct quic_stats_t {
    u64 pkt_count;
    u64 conn_count;
    u64 malformed_count;
    u64 handshake_count;
};

//keys used to identify connection ids. A QUIC connection is shared state between a client and a server.
//the Destination Connection ID is chosen by the recipient of the packet and is used to provide consistent routing; 
//the Source Connection ID is used to set the Destination Connection ID used by the peer.
//since the scid is static, only the dcid is needed to identify the connection
struct conn_id_key_t {
    u64 conn_id;
};

//stats for the connection ids, currently only monitoring the number of packets per connection
struct conn_id_stats_t {
    u64 pkt_count;
};

//maps to hold connection-level and ID-level stats
BPF_HASH(conn_stats, struct quic_key_t, struct quic_stats_t);
BPF_HASH(id_stats, struct conn_id_key_t, struct conn_id_stats_t);

//ring buffer for summarized telemetry
struct summary_t {
    u32 src_ip;
    u32 dst_ip;
    u64 pkt_count;
    u64 conn_count;
    u64 malformed_count;
    u64 handshake_count;
};

//output to a ring buffer "events" of size 8 pages or 32 KB
BPF_RING_BUF_OUTPUT(events, 8);


//we parse the QUIC header for packet type and connection ids
static inline int parse_quic_header(void *data, void *data_end, u64 *dcid, u64 *scid, u8 *pkt_type) {
	
	// QUIC header can only be before the data end
	//we only read the 18 bytes of the header (including data_end)
	//return an error if so
    if (data + 18 > data_end)
        return -1;

	//get the header data
    u8 *hdr = data;
	
	//packet type is the first byte of the header
    *pkt_type = hdr[0];
	
	//form byte 1 to 8 is dcid, from byte 9 to 17 is scid
    __builtin_memcpy(dcid, &hdr[1], sizeof(*dcid));
    __builtin_memcpy(scid, &hdr[9], sizeof(*scid));
	
	//return sucess
    return 0;
}


// Used to parse QUIC header specifically
// we will parse and filter all packets through four layers
// this will reduce the burden at each step
// Ethernet -> IP -> UDP -> QUIC header

//sk_buff is the main networking structure representing a packet.
//the program will be invoked on eack packets passing the network sockets that the BPF program binds to
//similar methodology to old BPF code
int monitor_quic(struct __sk_buff *skb) {
	
	//create pointer to packet data's start and its end (skb->data/data_end)
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;



	//[PART 1] getting header data and filtering for QUIC pakets

	//cast the packet header's data to the ethhdr struct (defined in uapi/linux/if_ether.h) (not ether_header) 
	// Basic structure of the ethhdr struct:
		//struct ethhdr {
		//	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
		//	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
		//	__be16		h_proto;		/* packet type ID field	*/
		//}
	
    struct ethhdr *eth = data;
	//verify if packet is within bound of header data
	//this is done by moving the pointer to the ethernet header forward by one
	//and then checking to see if the pointer point past the end
	//"void" is a generic pointer type; "void *" can be converted to any other pointer type without an explicit cast
	if ((void *)(eth + 1) > data_end)
        return 0;

	//[FILTER 1] IP packets only
	//filter for IPV4 packets using the h_proto attribute (packet type ID)
	//ETH_P_IP only captures incoming IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

	//create the pointer to after the ethernet header (by using the location of the data + the size of the ethernet header)
	//this is the location of the IP header. ALso check if pointer to ip is within bound
	//iphdr struct can be found in uapi/linux/ip.h
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return 0;

	//[FILTER 2] UPD packets only, since QUIC only runs over UPD
    if (ip->protocol != IPPROTO_UDP)
        return 0;
	
	// similarly create a pointer to the udp header
	//ip->ihl * 4 gets the size of the ip header in bytes (ihl is IP header length, but is in bits)
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    //verify that the pointer is within bound of the packet data
	if ((void *)(udp + 1) > data_end)
        return 0;

    // Skip filtering UDP header and cst the QUIC data instead
    void *quic_data = (void *)udp + sizeof(*udp);
    if (quic_data >= data_end)
        return 0;



    //[PART 2] Parse QUIC header using the parse_quic_header function and getting the information
	
	//store the connections ids and packet type
	//connection ids are 8 bytes and packets type is one byte
    u64 dcid = 0, scid = 0;
    u8 pkt_type = 0;
	
	//if the function returns a -1 instead of a 0
	//=> Error, Header is malformed
    if (parse_quic_header(quic_data, data_end, &dcid, &scid, &pkt_type) < 0) {
			
		//creates a key that identified the malformed QUIC connection
        struct quic_key_t key = {.src_ip = ip->saddr, .dst_ip = ip->daddr};
		
		//using the BPF funciton lookup_or_try_init()
		//look up the connection to see if it exist in the conn_stats map
		//if it does not, initialise a k-v pair with "key" as the key
		//and an empty struct of type quic_stats_t as the value (Done for safety, preventing pointer pointing to random address)
		//create a pointer to the quic_stats_t struct
        struct quic_stats_t *st = conn_stats.lookup_or_try_init(&key, &(struct quic_stats_t){});
        
		//increment the malformed packets count by one in the quic_stats_t struct
		//and exit the program
		if (st) st->malformed_count++;
        return 0;
    }

    //if header is not malformed
	//create a key to identify the connection
	//the key is made out of a pair containing the source IP and destination IP
    struct quic_key_t key = {.src_ip = ip->saddr, .dst_ip = ip->daddr};
	//find or create the quic_stats_t entry in the conn_stats map
    struct quic_stats_t *st = conn_stats.lookup_or_try_init(&key, &(struct quic_stats_t){});
    //verify that the entry exist, 
	//if it does not exit the program since we don't need to commit the packet
	if (!st)
        return 0;
	
	//increment the packet count by one
    st->pkt_count++;

    //detect if the packet is an initial handshake (QUIC Initial packet type = 0xC0 or 0xC1 depending on version)
	//and then increment the count
    if ((pkt_type & 0xF0) == 0xC0)
        st->handshake_count++;

    //track connection IDs statistics
	//create a key using the dcid since the scid is static
    struct conn_id_key_t cid_key = {.conn_id = dcid};
	//get or create the conn_id_stats_t for the connection
    struct conn_id_stats_t *cid_st = id_stats.lookup_or_try_init(&cid_key, &(struct conn_id_stats_t){});
    //verify that the entry exists
	if (cid_st)
		//increment the counter for the connection
        cid_st->pkt_count++;
		
		
	//[PART 3] Pushing telemetry data to the ring buffer

    //push summarized data every N packets to reduce performance overhead
	//currently pushes data once every 256 packets 
	//using the 0xFF mask (logical AND) to get the last 8 bits of the count, 
	//if the last 8 bits all equal to 0 => a cycle of 256 packets have been counted
	
    if ((st->pkt_count & 0xFF) == 0) {
		
        //create a summary of the last N packets
		struct summary_t summary = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .pkt_count = st->pkt_count,
            .conn_count = st->conn_count,
            .malformed_count = st->malformed_count,
            .handshake_count = st->handshake_count,
        };
		
		//push the summary to the ring buffer "events"
		//the bpf_ringbuf_output function
		//Copy size bytes from data into a ring buffer "ringbuf"
		//the summary will have the expected size of 40 * N bytes
        events.ringbuf_output(&summary, sizeof(summary), 0);
    }
	
	//exit the program
    return 0;
}
