#ifndef CLICK_DOSDEFENDER_HH
#define CLICK_DOSDEFENDER_HH
#include <click/batchelement.hh>
#include <click/hashtable.hh>
#include <time.h>
CLICK_DECLS


struct FlowTupleDD {
    uint32_t src_ip;    // Source IP address
    uint32_t dst_ip;    // Destination IP address
    uint16_t src_port;  // Source port number
    uint16_t dst_port;  // Destination port number
    uint8_t protocol;  // Protocol number 

    bool operator==(const FlowTupleDD& other) const {
        return (src_ip == other.src_ip && dst_ip == other.dst_ip &&
                src_port == other.src_port && dst_port == other.dst_port &&
                protocol == other.protocol);
    }

    inline hashcode_t hashcode() const;
};



#define ROT(v, r) ((v)<<(r) | ((unsigned)(v))>>(32-(r)))

inline hashcode_t FlowTupleDD::hashcode() const
{
    // more complicated hashcode, but causes less collision
    hashcode_t sx = CLICK_NAME(hashcode)(src_ip);
    hashcode_t dx = CLICK_NAME(hashcode)(dst_ip);
    return (ROT(sx, (src_port % 16) + 1) ^ ROT(dx, 31 - (dst_port % 16)))
	^ ((dst_port << 16) | src_port);
}

struct ddval {
    uint8_t drop;
    clock_t ts;
    uint32_t pkt_count;
};

class DosDefender : public SimpleElement<DosDefender> { public:

    DosDefender() CLICK_COLD;
    ~DosDefender() CLICK_COLD;

    const char *class_name() const              { return "DosDefender"; }
    const char *port_count() const              { return PORTS_1_1; }

    Packet *simple_action(Packet *);
private:
    HashTable<FlowTupleDD, ddval> dos_table;
};

CLICK_ENDDECLS
#endif