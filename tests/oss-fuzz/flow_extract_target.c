#include <config.h>
#include "fuzzer.h"
#include "dp-packet.h"
#include "flow.h"
#include "match.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct dp_packet packet;
    struct flow flow;
    struct match match;
    struct ofp10_match ext_match;

    dp_packet_use_const(&packet, data, size);
    flow_extract(&packet, &flow);

    // Convert flow to match
    match_wc_init(&match, &flow);
    ofputil_match_to_ofp10_match(&match, &ext_match);

    // Print match and packet
    char *ext_s = ofp10_match_to_string(&ext_match, NULL, 2);
    ofp_print_packet(stdout, dp_packet_data(&packet), dp_packet_size(&packet), htonl(PT_ETH));
    ovs_hex_dump(stdout, dp_packet_data(&packet), dp_packet_size(&packet), 0, true);
    match_print(&match, NULL);
    printf("Actually extracted flow:\n%s\n", ext_s);
    ovs_hex_dump(stdout, &ext_match, sizeof ext_match, 0, false);
    free(ext_s);

    return 0;
}
