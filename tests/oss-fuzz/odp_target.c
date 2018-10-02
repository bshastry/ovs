#include <config.h>
#include "fuzzer.h"
#undef NDEBUG
#include "odp-util.h"
#include <stdio.h>
#include "openvswitch/dynamic-string.h"
#include "flow.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "util.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/vlog.h"
#include "random.h"

static const int num_filters = 10;
const char *filters[num_filters] = {
    "filter='dl_type=0x1235'",
    "filter='dl_vlan=99'",
    "filter='dl_vlan=99,ip'",
    "filter='ip,nw_src=35.8.2.199'",
    "filter='ip,nw_dst=172.16.0.199'",
    "filter='dl_type=0x0800,nw_src=35.8.2.199,nw_dst=172.16.0.199'",
    "filter='icmp,nw_src=35.8.2.199'",
    "filter='arp,arp_spa=1.2.3.5'",
    "filter='tcp,tp_src=90'",
    "filter='tcp6,tp_src=90'"
};

static int
parse_keys(bool wc_keys, const char *in)
{
    int exit_code = 0;

    enum odp_key_fitness fitness;
    struct ofpbuf odp_key;
    struct ofpbuf odp_mask;
    struct flow flow;
    struct ds out;
    int error;

    /* Convert string to OVS DP key. */
    ofpbuf_init(&odp_key, 0);
    ofpbuf_init(&odp_mask, 0);
    error = odp_flow_from_string(in, NULL,
                                 &odp_key, &odp_mask);
    if (error) {
        printf("odp_flow_from_string: error\n");
        goto next;
    }

    if (!wc_keys) {
        struct odp_flow_key_parms odp_parms = {
            .flow = &flow,
            .support = {
                .recirc = true,
                .ct_state = true,
                .ct_zone = true,
                .ct_mark = true,
                .ct_label = true,
                .max_vlan_headers = SIZE_MAX,
            },
        };

        /* Convert odp_key to flow. */
        fitness = odp_flow_key_to_flow(odp_key.data, odp_key.size, &flow);
        switch (fitness) {
            case ODP_FIT_PERFECT:
                break;

            case ODP_FIT_TOO_LITTLE:
                printf("ODP_FIT_TOO_LITTLE: ");
                break;

            case ODP_FIT_TOO_MUCH:
                printf("ODP_FIT_TOO_MUCH: ");
                break;

            case ODP_FIT_ERROR:
                printf("odp_flow_key_to_flow: error\n");
                goto next;
        }
        /* Convert cls_rule back to odp_key. */
        ofpbuf_uninit(&odp_key);
        ofpbuf_init(&odp_key, 0);
        odp_flow_key_from_flow(&odp_parms, &odp_key);

        if (odp_key.size > ODPUTIL_FLOW_KEY_BYTES) {
            printf ("too long: %"PRIu32" > %d\n",
                    odp_key.size, ODPUTIL_FLOW_KEY_BYTES);
            exit_code = 1;
        }
    }

    /* Convert odp_key to string. */
    ds_init(&out);
    if (wc_keys) {
        odp_flow_format(odp_key.data, odp_key.size,
                        odp_mask.data, odp_mask.size, NULL, &out, false);
    } else {
        odp_flow_key_format(odp_key.data, odp_key.size, &out);
    }
    puts(ds_cstr(&out));
    ds_destroy(&out);

next:
    ofpbuf_uninit(&odp_key);
    ofpbuf_uninit(&odp_mask);

    return exit_code;
}

static int
parse_actions(const char *in)
{
    struct ofpbuf odp_actions;
    struct ds out;
    int error;

    /* Convert string to OVS DP actions. */
    ofpbuf_init(&odp_actions, 0);
    error = odp_actions_from_string(in, NULL, &odp_actions);
    if (error) {
        printf("odp_actions_from_string: error\n");
        goto next;
    }

    /* Convert odp_actions back to string. */
    ds_init(&out);
    format_odp_actions(&out, odp_actions.data, odp_actions.size, NULL);
    puts(ds_cstr(&out));
    ds_destroy(&out);

next:
    ofpbuf_uninit(&odp_actions);
    return 0;
}

static int
parse_filter(const char *filter_parse, const char *in)
{
    struct flow flow_filter;
    struct flow_wildcards wc_filter;
    char *error, *filter = NULL;

    if (filter_parse && !strncmp(filter_parse, "filter=", 7)) {
        filter = xstrdup(filter_parse + 7);
        memset(&flow_filter, 0, sizeof(flow_filter));
        memset(&wc_filter, 0, sizeof(wc_filter));

        error = parse_ofp_exact_flow(&flow_filter, &wc_filter, NULL, filter,
                                     NULL);
        if (error) {
            ovs_fatal(0, "Failed to parse filter (%s)", error);
        }
    } else {
        ovs_fatal(0, "No filter to parse.");
    }

    struct ofpbuf odp_key;
    struct ofpbuf odp_mask;
    struct ds out;

    /* Convert string to OVS DP key. */
    ofpbuf_init(&odp_key, 0);
    ofpbuf_init(&odp_mask, 0);
    if (odp_flow_from_string(in, NULL, &odp_key, &odp_mask)) {
        printf("odp_flow_from_string: error\n");
        goto next;
    }

    if (filter) {
        struct flow flow;
        struct flow_wildcards wc;
        struct match match, match_filter;
        struct minimatch minimatch;

        odp_flow_key_to_flow(odp_key.data, odp_key.size, &flow);
        odp_flow_key_to_mask(odp_mask.data, odp_mask.size, &wc, &flow);
        match_init(&match, &flow, &wc);

        match_init(&match_filter, &flow_filter, &wc);
        match_init(&match_filter, &match_filter.flow, &wc_filter);
        minimatch_init(&minimatch, &match_filter);

        if (!minimatch_matches_flow(&minimatch, &match.flow)) {
            minimatch_destroy(&minimatch);
            goto next;
        }
        minimatch_destroy(&minimatch);
    }
    /* Convert odp_key to string. */
    ds_init(&out);
    odp_flow_format(odp_key.data, odp_key.size,
                    odp_mask.data, odp_mask.size, NULL, &out, false);
    puts(ds_cstr(&out));
    ds_destroy(&out);

next:
    ofpbuf_uninit(&odp_key);
    ofpbuf_uninit(&odp_mask);

    free(filter);
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Bail out if we cannot construct at least a 1 char string. */
    const char *input = (const char *) data;
    if (size < 2 || input[size - 1] != '\0' || strchr(input, '\n')) {
        return 0;
    }

    /* Disable logging to avoid write to disk. */
    static bool isInit = false;
    if (!isInit) {
        vlog_set_verbosity("off");
        isInit = true;
    }

    /* Parse keys and wc keys. */
    parse_keys(false, input);
    parse_keys(true, input);

    /* Parse actions. */
    parse_actions(input);

    /* Parse filter. */
    /* TODO: Add filter string. */
    parse_filter(filters[random_range(num_filters)], input);

    return 0;
}
