#ifndef CLICK_DEEPPACKETINSPECT_HH
#define CLICK_DEEPPACKETINSPECT_HH
#include <click/batchelement.hh>
#include <click/hashtable.hh>
CLICK_DECLS


struct FlowTupleDPI {
    uint32_t src_ip;    // Source IP address
    uint32_t dst_ip;    // Destination IP address
    uint16_t src_port;  // Source port number
    uint16_t dst_port;  // Destination port number
    uint8_t protocol;  // Protocol number 

    bool operator==(const FlowTupleDPI& other) const {
        return (src_ip == other.src_ip && dst_ip == other.dst_ip &&
                src_port == other.src_port && dst_port == other.dst_port &&
                protocol == other.protocol);
    }

    inline hashcode_t hashcode() const;
};



#define ROT(v, r) ((v)<<(r) | ((unsigned)(v))>>(32-(r)))

inline hashcode_t FlowTupleDPI::hashcode() const
{
    // more complicated hashcode, but causes less collision
    hashcode_t sx = CLICK_NAME(hashcode)(src_ip);
    hashcode_t dx = CLICK_NAME(hashcode)(dst_ip);
    return (ROT(sx, (src_port % 16) + 1) ^ ROT(dx, 31 - (dst_port % 16)))
	^ ((dst_port << 16) | src_port);
}

class DeepPacketInspect : public SimpleElement<DeepPacketInspect> { public:

    DeepPacketInspect() CLICK_COLD;
    ~DeepPacketInspect() CLICK_COLD;

    const char *class_name() const              { return "DeepPacketInspect"; }
    const char *port_count() const              { return PORTS_1_1; }

    Packet *simple_action(Packet *);
private:
    HashTable<FlowTupleDPI, uint8_t> dpi_table;
};

CLICK_ENDDECLS
#endif