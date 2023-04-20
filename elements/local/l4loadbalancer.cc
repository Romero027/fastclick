#include <click/config.h>
#include "l4loadbalancer.hh"
CLICK_DECLS

#define SERVER_IP 0xC0A80001
                      
uint32_t current_ip = 0x0A000001; // initialize to 10.0.0.1
uint16_t current_port = 10000; // initialize to 0

L4LoadBalancer::L4LoadBalancer() : connection_table(new HashTableMP<FlowTuple, ServerAddr>())
{
    connection_table->resize_clear(40000000);
}

L4LoadBalancer::~L4LoadBalancer()
{
    delete connection_table;
}

uint32_t get_next_ip() {
    current_ip++;
    if (current_ip > 0x0A00FFFE) { // wrap around to 10.0.0.1
        current_ip = 0x0A000001;
    }
    return current_ip;
}

uint16_t get_next_port() {
    current_port++;
    if (current_port > 60000) { 
        current_port = 10000;
    }
    return current_port;
}

void
L4LoadBalancer::push_batch(int, PacketBatch* batch)
{
	EXECUTE_FOR_EACH_PACKET(simple_action, batch);
	output_push_batch(0, batch);
}

Packet *
L4LoadBalancer::simple_action(Packet *p) {
    // click_chatter("Received a packet of size %d !", p->length());

    // Extract 5 tuple
    const click_ip *iph = p->ip_header();
    // click_chatter("Checkpoint 1");
    const click_tcp *tcph = p->tcp_header();
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    uint16_t src_port = tcph->th_sport;
    uint16_t dst_port = tcph->th_dport;
    uint8_t protocol = iph->ip_p;
    FlowTuple f = {src_ip, dst_ip, src_port, dst_port, protocol};

    // click_chatter("Checkpoint ");
    // IPAddress server_ip;
    // uint16_t server_port;

    bool first = false;
    auto ptr = connection_table->find_create(f, [this,&first](){
        IPAddress server_ip = IPAddress(get_next_ip());
        uint16_t server_port = get_next_port();
        first= true;
        return ServerAddr{server_ip, server_port};
    });

    ServerAddr addr = *ptr;

    // m.lock()
    // if (connection_table.find(f) == connection_table.end()) {
    //     // new flow
    //     server_ip = IPAddress(get_next_ip());
    //     server_port = get_next_port();
    //     connection_table[f] = {server_ip, server_port};
    // } else {
    //     // existing flow
    //     server_ip = connection_table[f].addr;
    //     server_port = connection_table[f].port;
    // }   
    // // m.unlock();
    // // click_chatter("Checkpoint 3");
    WritablePacket* q =p->uniqueify();
    p = q;

    q->ip_header()->ip_dst = addr.addr;
    q->tcp_header()->th_dport = addr.port;
    // p->set_dst_ip_anno(server_ip);

    // click_chatter("Destination IP is %u\n", p->ip_header()->ip_dst.s_addr);
    // click_chatter("Destination Port is %u\n", p->tcp_header()->th_dport);
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(L4LoadBalancer)
ELEMENT_MT_SAFE(L4LoadBalancer)