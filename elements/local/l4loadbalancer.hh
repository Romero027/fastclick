#ifndef CLICK_L4LOADBALANCER_HH
#define CLICK_L4LOADBALANCER_HH
#include <unordered_map>
#include <mutex>
#include <click/batchelement.hh>
CLICK_DECLS


struct FlowTuple {
    uint32_t src_ip;    // Source IP address
    uint32_t dst_ip;    // Destination IP address
    uint16_t src_port;  // Source port number
    uint16_t dst_port;  // Destination port number
    uint8_t protocol;  // Protocol number 

    bool operator==(const FlowTuple& other) const {
        return (src_ip == other.src_ip && dst_ip == other.dst_ip &&
                src_port == other.src_port && dst_port == other.dst_port &&
                protocol == other.protocol);
    }
};

struct FlowTupleHash {
    std::size_t operator()(const FlowTuple& ft) const {
        std::size_t hash = 17;
        hash = hash * 31 + std::hash<unsigned int>()(ft.src_ip);
        hash = hash * 31 + std::hash<unsigned int>()(ft.dst_ip);
        hash = hash * 31 + std::hash<unsigned short>()(ft.src_port);
        hash = hash * 31 + std::hash<unsigned short>()(ft.dst_port);
        hash = hash * 31 + std::hash<unsigned char>()(ft.protocol);
        return hash;
    }
};

struct FlowTupleEqual {
    bool operator()(const FlowTuple& ft1, const FlowTuple& ft2) const {
        return (ft1 == ft2);
    }
};


class L4LoadBalancer : public SimpleElement<L4LoadBalancer> { public:

    L4LoadBalancer() CLICK_COLD;
    ~L4LoadBalancer() CLICK_COLD;

    const char *class_name() const              { return "L4LoadBalancer"; }
    const char *port_count() const              { return PORTS_1_1; }

    Packet *simple_action(Packet *);
private:
    // Connection table: Flow 5 tuple -> server ip
    std::unordered_map<FlowTuple, IPAddress, FlowTupleHash, FlowTupleEqual> connection_table;
    std::mutex m;
};

CLICK_ENDDECLS
#endif