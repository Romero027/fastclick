#include <click/config.h>
#include "deeppacketinspect.hh"
CLICK_DECLS

#define PATTERN "adsoqweipoqentqwppoqkeqwjeqwokfjsdfhlvoppdaqweqdasdgreqererqweqw"
#define STRING_PATTERN_MAX_LENGTH 1000
static uint8_t pat[STRING_PATTERN_MAX_LENGTH];
static uint32_t lps[STRING_PATTERN_MAX_LENGTH];
static uint32_t pat_length = 0;

void computeLPSArray(void)
{
    uint32_t len = 0, i = 1;
    lps[0] = 0;
    while (i < pat_length) {
        if (pat[i] == pat[len]) {
            len++;
            lps[i] = len;
            i++;
        }else {
            if (len != 0) {
                len = lps[len - 1];
            }else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

bool KMPSearch(const unsigned char* txt, uint32_t N)
{
    uint32_t i = 0, j = 0; 
    while ((N - i) >= (pat_length - j)) {
        if (pat[j] == txt[i]) {
            j++;
            i++;
        }
        if (j == pat_length) {
            return true;
        } else if (i < N && pat[j] != txt[i]) {
            if (j != 0)
                j = lps[j - 1];
            else
                i = i + 1;
        }
    }
    return false;
}

DeepPacketInspect::DeepPacketInspect()
{
    pat_length = sizeof(PATTERN) - 1;
    for (uint32_t i = 0; i < pat_length; i++){
        pat[i] = PATTERN[i];
    }
    computeLPSArray();
}

DeepPacketInspect::~DeepPacketInspect()
{
    dpi_table.clear();
}


Packet *
DeepPacketInspect::simple_action(Packet *p) {

    // Extract 5 tuple
    const click_ip *iph = p->ip_header();
    const click_tcp *tcph = p->tcp_header();
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;
    uint16_t src_port = tcph->th_sport;
    uint16_t dst_port = tcph->th_dport;
    uint8_t protocol = iph->ip_p;
    FlowTupleDPI f = {src_ip, dst_ip, src_port, dst_port, protocol};

    uint8_t drop = 0;
    if (dpi_table.find(f) == dpi_table.end()) {
        dpi_table[f] = 0;
    } else {
        drop = dpi_table[f];
    }

    const unsigned char* payload = p->getPacketContent();
    uint16_t payload_len = p->getPacketContentSize();
    if (drop == 0 && KMPSearch(payload, payload_len)) {
        dpi_table[f] = 1;
    }

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DeepPacketInspect)
ELEMENT_MT_SAFE(DeepPacketInspect)