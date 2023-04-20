#include <click/config.h>
#include "heavyhitter.hh"
CLICK_DECLS
                      
HeavyHitter::HeavyHitter() : count_table(new HashTableMP<FlowTupleHH, int64_t>())
{
   count_table->resize_clear(100000000);
}

HeavyHitter::~HeavyHitter()
{
    delete count_table;
}

void
HeavyHitter::push_batch(int, PacketBatch* batch)
{
	EXECUTE_FOR_EACH_PACKET(simple_action, batch);
	output_push_batch(0, batch);
}

Packet *
HeavyHitter::simple_action(Packet *p) {
    // Extract 5 tuple
    const click_ip *iph = p->ip_header();
    const click_tcp *tcph = p->tcp_header();
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    uint16_t src_port = tcph->th_sport;
    uint16_t dst_port = tcph->th_dport;
    uint8_t protocol = iph->ip_p;
    FlowTupleHH f = {src_ip, dst_ip, src_port, dst_port, protocol};


    // if (count_table.find(f) == count_table.end()) {i
    //     // new flow
    //     count_table[f] = 0;
    // } else {
    //     // existing flow
    //     // count_table[f]++;
    // }   

    bool first = false;
    auto ptr = count_table->find_create(f, [this,&first](){
        int id = 0;first= true;return id;
        //click_chatter("Creating id %d",id);
    });

    int count = *ptr;
    count_table->insert(f, count);

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HeavyHitter)
ELEMENT_MT_SAFE(HeavyHitter)