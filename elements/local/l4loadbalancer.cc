#include <click/config.h>
#include "l4loadbalancer.hh"
CLICK_DECLS

#define SERVER_IP 0xC0A80001

L4LoadBalancer::L4LoadBalancer()
{
}

L4LoadBalancer::~L4LoadBalancer()
{
    connection_table.clear();
}


Packet *
L4LoadBalancer::simple_action(Packet *p) {
    click_chatter("Received a packet of size %d !", p->length());

    // Extract 5 tuple
    const click_ip *iph = p->ip_header();
    const click_tcp *tcph = p->tcp_header();
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    uint16_t src_port = tcph->th_sport;
    uint16_t dst_port = tcph->th_dport;
    uint8_t protocol = iph->ip_p;
    FlowTuple f = {src_ip, dst_ip, src_port, dst_port, protocol};

    IPAddress server_ip = IPAddress(SERVER_IP);
    m.lock();
    if (connection_table.find(f) == connection_table.end()) {
        // new flow
        connection_table[f] = server_ip;
    } else {
        // existing flow
        server_ip = connection_table[f];
    }   
    m.unlock();

    WritablePacket* q =p->uniqueify();
    p = q;

    q->ip_header()->ip_dst = server_ip;
    p->set_dst_ip_anno(server_ip);

    click_chatter("Destination IP is %u\n", p->ip_header()->ip_dst.s_addr);
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(L4LoadBalancer)