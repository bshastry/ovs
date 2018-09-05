#include <config.h>
#include "fuzzer.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/match.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct dp_packet packet;
    struct flow flow;
    struct flowmap fmap;
    struct match match;
    struct match flow_metadata;
    struct ofp10_match ext_match;

    dp_packet_use_const(&packet, data, size);
    flow_extract(&packet, &flow);

    // Extract flowmap
    flow_wc_map(&flow, &fmap);

    // Extract metadata
    flow_get_metadata(&flow, &flow_metadata);

    // Hashing functions
    uint32_t hash = flow_hash_5tuple(&flow, 0);
    hash = flow_hash_symmetric_l4(&flow, 0);
    hash = flow_hash_symmetric_l2(&flow, 0);
    hash = flow_hash_symmetric_l3l4(&flow, 0, NULL);

    // Convert flow to match
    match_wc_init(&match, &flow);
    ofputil_match_to_ofp10_match(&match, &ext_match);

    // Print match and packet
    ofp_print_packet(stdout, dp_packet_data(&packet), dp_packet_size(&packet), htonl(PT_ETH));
    ovs_hex_dump(stdout, dp_packet_data(&packet), dp_packet_size(&packet), 0, true);
    match_print(&match, NULL);

    ovs_hex_dump(stdout, &ext_match, sizeof ext_match, 0, false);
    return 0;
}
