#include <click/config.h>
#include "dosdefender.hh"
CLICK_DECLS
                      
DosDefender::DosDefender(): dos_table(new HashTableMP<FlowTupleDD, ddval>())
{
    dos_table->resize_clear(40000000);
}

DosDefender::~DosDefender()
{
    delete dos_table;
}

void
DosDefender::push_batch(int, PacketBatch* batch)
{
	EXECUTE_FOR_EACH_PACKET(simple_action, batch);
	output_push_batch(0, batch);
}



Packet *
DosDefender::simple_action(Packet *p) {

    // Extract 5 tuple
    const click_ip *iph = p->ip_header();
    const click_tcp *tcph = p->tcp_header();
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    uint16_t src_port = tcph->th_sport;
    uint16_t dst_port = tcph->th_dport;
    uint8_t protocol = iph->ip_p;
    FlowTupleDD f = {src_ip, dst_ip, src_port, dst_port, protocol};

    bool first = false;
    auto ptr = dos_table->find_create(f, [this,&first](){
        return ddval{0, clock(), 1};
    });

    if (!first) {
        ptr->pkt_count++;
    }

    clock_t now = clock();
    if (now - ptr->ts > 100 && ptr->drop == 0) {
        if (ptr->pkt_count > 100) {
            ptr->drop = 1;
        }
        ptr->pkt_count = 0;
        ptr->ts = clock();
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DosDefender)
ELEMENT_MT_SAFE(DosDefender)