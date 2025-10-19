#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/if_ether.h>
#include <bcc/proto.h>

#define MAX_GROUP_THRESHOLD 4096
#define MIN_GROUP_THRESHOLD 1
#define TIME_WINDOW (100 * 1000000ULL)

BPF_PERF_OUTPUT(events);

struct q_key_t {
    u32 src_ip;
    u32 dst_ip;
};

struct q_stats_t {
    u64 pkt_count;
    u64 malformed_count;
	u64 initial_count;
    u64 handshake_count;
	
	u16 threshold;
	u64 last_transmit_time;
};

BPF_HASH(quic_stats, struct q_key_t, struct q_stats_t);

struct summary_t {
    u32 src_ip;
    u32 dst_ip;
    u64 pkt_count;

    u64 malformed_count;
	u64 initial_count;
    u64 handshake_count;
};

static inline int parse_quic_header(struct __sk_buff *skb, u32 offset, u32 end_offset) {

    if ((offset + 1) > end_offset)
        return 255; 

    u8 first_byte;
	if (bpf_skb_load_bytes(skb, offset, &first_byte, sizeof(first_byte)) < 0)
		return 255;

	if ((first_byte & 0x80) == 0x80) { 

		if ((offset + 7) > end_offset)	
			return 255; 

		if ((first_byte & 0xF0) == 0xE0) { 
			return 4;

		} else if ((first_byte & 0xF0) == 0xC0) { 
			return 2;
		} 

		return 1;

	} else {

		if ((offset + 3) > end_offset)	return 255; 
			return 0;
	}
}

int monitor_quic(struct __sk_buff *skb) {

	struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    
	u32 offset = ETH_HLEN;
    
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) return 0;
	
    if (eth.h_proto != htons(ETH_P_IP)) return 0;
    
	if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0) return 0;
    
	if (ip.protocol != 17) return 0; // UDP
    
	offset += ip.ihl * 4;
    
	if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0) return 0;
    
	if (udp.dest != htons(443)) {
        if (udp.source != htons(443)) {
            return 0;
        }
    } 
	
	offset += sizeof(udp);
	
	u32 end_offset = offset + (bpf_ntohs(udp.len) - sizeof(udp));
	
	/*
	u32 offset = 0;

	struct ethernet_t eth_hdr;
	if (bpf_skb_load_bytes(skb, offset, &eth_hdr, sizeof(eth_hdr)) < 0)
		return 0;

	if (eth_hdr.type != 0x0800) 
		return 0;

	offset += sizeof(eth_hdr);

	struct ip_t ip_hdr;
	if (bpf_skb_load_bytes(skb, offset, &ip_hdr, sizeof(ip_hdr)) < 0)
		return 0;

	if (ip_hdr.nextp != IP_UDP)
		return 0;

    u32 ip_header_length = ip_hdr.hlen << 2;  
	if (ip_header_length < IP_HLEN) 
		return 0;

	offset += ip_header_length;

	struct udp_t udp_hdr;
	if (bpf_skb_load_bytes(skb, offset, &udp_hdr, sizeof(udp_hdr)) < 0)
		return 0;

	u32 udp_length = bpf_ntohs(udp_hdr.length);

	offset += sizeof(udp_hdr);

	u32 end_offset = offset + (udp_length - sizeof(udp_hdr));

    if (udp_hdr.sport != 443 && udp_hdr.dport != 443)
       return 0;
	*/
	
	
	u8 pkt_type = parse_quic_header(skb, offset, end_offset);

	struct q_key_t key;
	key.src_ip = ip.saddr;
	key.dst_ip = ip.daddr;

	struct q_stats_t init_stats = {0};
	struct q_stats_t *lookup_stats = quic_stats.lookup_or_try_init(&key, &init_stats);

	if (!lookup_stats) {
		return 0;
	}
	
	//initialise threshold and time keeping variable
	if (lookup_stats->threshold == 0) {
        lookup_stats->threshold = MIN_GROUP_THRESHOLD;
	}
	if (lookup_stats->last_transmit_time == 0) {
        lookup_stats->last_transmit_time = bpf_ktime_get_ns();
	}
	
	lookup_stats->pkt_count++;

	if (pkt_type == 4) {
		lookup_stats->handshake_count++;
	} else if (pkt_type == 2) {
		lookup_stats->initial_count++;
	} else if (pkt_type == 255) {
		lookup_stats->malformed_count++;
	}
	
	
	
	//transmit if the packet count is larger than the threshold
    if (lookup_stats->pkt_count >= lookup_stats->threshold) {

		struct summary_t summary = {
            .src_ip = key.src_ip,
            .dst_ip = key.dst_ip,
            .pkt_count = lookup_stats->pkt_count,
            .malformed_count = lookup_stats->malformed_count,
            .initial_count = lookup_stats->initial_count,
            .handshake_count = lookup_stats->handshake_count,
        };

        events.perf_submit(skb, &summary, sizeof(summary));
		
		
		//calculate the time between transmission
		u64 now = bpf_ktime_get_ns();
		u64 elapsed = now - lookup_stats->last_transmit_time;
		
		if (elapsed < TIME_WINDOW) {
			if (lookup_stats->threshold < MAX_GROUP_THRESHOLD) {
				lookup_stats->threshold <<= 1; //left shift by one bit, doubling the threshold
			}
		} else {
			if (lookup_stats->threshold > MIN_GROUP_THRESHOLD) {
				lookup_stats->threshold >>= 1; //right shift by one bit, halving the threshold
			}
		}
		
		//clear value for next transmission
		lookup_stats->pkt_count = 0;
        lookup_stats->malformed_count = 0;
        lookup_stats->initial_count = 0;
        lookup_stats->handshake_count = 0;
        lookup_stats->last_transmit_time = now;

    }

    return 0;
}
