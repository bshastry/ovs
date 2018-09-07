#include <config.h>
#include "fuzzer.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/match.h"

static void test_miniflow(struct flow *flow)
{
    struct miniflow *miniflow;
    struct miniflow *miniflow, *miniflow2, *miniflow3;
    struct flow flow2, flow3;
    int i;

    const uint64_t *flow_u64 = (const uint64_t *) flow;

    /* Convert flow to miniflow. */
    miniflow = miniflow_create(flow);

    /* Check that the flow equals its miniflow. */
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        assert(miniflow_get_vid(miniflow, i) ==
               vlan_tci_to_vid(flow.vlans[i].tci));
    }
    for (i = 0; i < FLOW_U64S; i++) {
        assert(miniflow_get(miniflow, i) == flow_u64[i]);
    }

    /* Check that the miniflow equals itself. */
    assert(miniflow_equal(miniflow, miniflow));

    /* Convert miniflow back to flow and verify that it's the same. */
    miniflow_expand(miniflow, &flow2)
    assert(flow_equal(&flow, &flow2));
    /* Check that copying a miniflow works properly. */
    miniflow2 = miniflow_clone__(miniflow);
    assert(miniflow_equal(miniflow, miniflow2));
    assert(miniflow_hash__(miniflow, 0) == miniflow_hash__(miniflow2, 0));
    miniflow_expand(miniflow2, &flow3);
    assert(flow_equal(&flow, &flow3));

    free(miniflow);
    free(miniflow2);
    free(miniflow3);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct dp_packet packet;
    struct flow flow;
    dp_packet_use_const(&packet, data, size);
    flow_extract(&packet, &flow);

    /* Extract flowmap. */
    struct flowmap fmap;
    flow_wc_map(&flow, &fmap);

    /* Test miniflow. */
    test_miniflow(&flow);

    /* Parse TCP flags. */
    if (dp_packet_size(&packet) >= ETH_HEADER_LEN) {
        uint16_t tcp_flags = parse_tcp_flags(&packet);
        ignore(tcp_flags);
    }

    /* Extract metadata. */
    struct match flow_metadata;
    flow_get_metadata(&flow, &flow_metadata);

    /* Hashing functions. */
    uint32_t hash = flow_hash_5tuple(&flow, 0);
    hash = flow_hash_symmetric_l4(&flow, 0);
    hash = flow_hash_symmetric_l2(&flow, 0);
    hash = flow_hash_symmetric_l3l4(&flow, 0, NULL);
    ignore(hash);

    /* Convert flow to match. */
    struct match match;
    match_wc_init(&match, &flow);

    struct ofp10_match ext_match;
    ofputil_match_to_ofp10_match(&match, &ext_match);

    /* Print match and packet. */
    ofp_print_packet(stdout, dp_packet_data(&packet), dp_packet_size(&packet),
                     htonl(PT_ETH));
    ovs_hex_dump(stdout, dp_packet_data(&packet), dp_packet_size(&packet), 0,
                 true);
    match_print(&match, NULL);

    ovs_hex_dump(stdout, &ext_match, sizeof ext_match, 0, false);

    return 0;
}
