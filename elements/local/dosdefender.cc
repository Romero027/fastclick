#include <click/config.h>
#include "dosdefender.hh"
CLICK_DECLS
                      
DosDefender::DosDefender()
{
}

DosDefender::~DosDefender()
{
    dos_table.clear();
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

    if (dos_table.find(f) == dos_table.end()) {
        // new flow
        dos_table[f] = {0, clock(), 1};
    } else {
        // existing flow
        clock_t now = clock();
        if (now - dos_table[f].ts > 100 && dos_table[f].drop == 0) {
            if (dos_table[f].pkt_count > 100) {
                dos_table[f].drop = 1;
            }
            dos_table[f].pkt_count = 0;
            dos_table[f].ts = clock();
        }
    }   

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DosDefender)
ELEMENT_MT_SAFE(DosDefender)