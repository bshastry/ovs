#include <config.h>
#include "fuzzer.h"
#include <errno.h>
#include <getopt.h>
#include <sys/wait.h>

#include "command-line.h"
#include "dp-packet.h"
#include "fatal-signal.h"
#include "flow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "ovn/lib/logical-fields.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/extend-table.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "util.h"

static void
create_symtab(struct shash *symtab)
{
    ovn_init_symtab(symtab);

    /* For negative testing. */
    expr_symtab_add_field(symtab, "bad_prereq", MFF_XREG0, "xyzzy", false);
    expr_symtab_add_field(symtab, "self_recurse", MFF_XREG0,
                          "self_recurse != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_1", MFF_XREG0,
                          "mutual_recurse_2 != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_2", MFF_XREG0,
                          "mutual_recurse_1 != 0", false);
    expr_symtab_add_string(symtab, "big_string", MFF_XREG0, NULL);
}

static void
create_gen_opts(struct hmap *dhcp_opts, struct hmap *dhcpv6_opts,
                struct hmap *nd_ra_opts)
{
    hmap_init(dhcp_opts);
    dhcp_opt_add(dhcp_opts, "offerip", 0, "ipv4");
    dhcp_opt_add(dhcp_opts, "netmask", 1, "ipv4");
    dhcp_opt_add(dhcp_opts, "router",  3, "ipv4");
    dhcp_opt_add(dhcp_opts, "dns_server", 6, "ipv4");
    dhcp_opt_add(dhcp_opts, "log_server", 7, "ipv4");
    dhcp_opt_add(dhcp_opts, "lpr_server",  9, "ipv4");
    dhcp_opt_add(dhcp_opts, "domain", 15, "str");
    dhcp_opt_add(dhcp_opts, "swap_server", 16, "ipv4");
    dhcp_opt_add(dhcp_opts, "policy_filter", 21, "ipv4");
    dhcp_opt_add(dhcp_opts, "router_solicitation",  32, "ipv4");
    dhcp_opt_add(dhcp_opts, "nis_server", 41, "ipv4");
    dhcp_opt_add(dhcp_opts, "ntp_server", 42, "ipv4");
    dhcp_opt_add(dhcp_opts, "server_id",  54, "ipv4");
    dhcp_opt_add(dhcp_opts, "tftp_server", 66, "ipv4");
    dhcp_opt_add(dhcp_opts, "classless_static_route", 121, "static_routes");
    dhcp_opt_add(dhcp_opts, "ip_forward_enable",  19, "bool");
    dhcp_opt_add(dhcp_opts, "router_discovery", 31, "bool");
    dhcp_opt_add(dhcp_opts, "ethernet_encap", 36, "bool");
    dhcp_opt_add(dhcp_opts, "default_ttl",  23, "uint8");
    dhcp_opt_add(dhcp_opts, "tcp_ttl", 37, "uint8");
    dhcp_opt_add(dhcp_opts, "mtu", 26, "uint16");
    dhcp_opt_add(dhcp_opts, "lease_time",  51, "uint32");
    dhcp_opt_add(dhcp_opts, "wpad", 252, "str");

    /* DHCPv6 options. */
    hmap_init(dhcpv6_opts);
    dhcp_opt_add(dhcpv6_opts, "server_id",  2, "mac");
    dhcp_opt_add(dhcpv6_opts, "ia_addr",  5, "ipv6");
    dhcp_opt_add(dhcpv6_opts, "dns_server",  23, "ipv6");
    dhcp_opt_add(dhcpv6_opts, "domain_search",  24, "str");

    /* IPv6 ND RA options. */
    hmap_init(nd_ra_opts);
    nd_ra_opts_init(nd_ra_opts);
}

static void
create_addr_sets(struct shash *addr_sets)
{
    shash_init(addr_sets);

    static const char *const addrs1[] = {
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    };
    static const char *const addrs2[] = {
        "::1", "::2", "::3",
    };
    static const char *const addrs3[] = {
        "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03",
    };
    static const char *const addrs4[] = { NULL };

    expr_const_sets_add(addr_sets, "set1", addrs1, 3, true);
    expr_const_sets_add(addr_sets, "set2", addrs2, 3, true);
    expr_const_sets_add(addr_sets, "set3", addrs3, 3, true);
    expr_const_sets_add(addr_sets, "set4", addrs4, 0, true);
}

static void
create_port_groups(struct shash *port_groups)
{
    shash_init(port_groups);

    static const char *const pg1[] = {
        "lsp1", "lsp2", "lsp3",
    };
    static const char *const pg2[] = { NULL };

    expr_const_sets_add(port_groups, "pg1", pg1, 3, false);
    expr_const_sets_add(port_groups, "pg_empty", pg2, 0, false);
}

static bool
lookup_port_cb(const void *ports_, const char *port_name, unsigned int *portp)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (!node) {
        return false;
    }
    *portp = node->data;
    return true;
}

static bool
is_chassis_resident_cb(const void *ports_, const char *port_name)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (node) {
        return true;
    }
    return false;
}

static void
test_parse_actions(struct ds *input)
{
    struct shash symtab;
    struct hmap dhcp_opts;
    struct hmap dhcpv6_opts;
    struct hmap nd_ra_opts;
    struct simap ports;
    bool ok = true;

    create_symtab(&symtab);
    create_gen_opts(&dhcp_opts, &dhcpv6_opts, &nd_ra_opts);

    /* Initialize group ids. */
    struct ovn_extend_table group_table;
    ovn_extend_table_init(&group_table);

    /* Initialize meter ids for QoS. */
    struct ovn_extend_table meter_table;
    ovn_extend_table_init(&meter_table);

    simap_init(&ports);
    simap_put(&ports, "eth0", 5);
    simap_put(&ports, "eth1", 6);
    simap_put(&ports, "LOCAL", ofp_to_u16(OFPP_LOCAL));

    struct ofpbuf ovnacts;
    struct expr *prereqs;
    char *error;

    puts(ds_cstr(input));

    ofpbuf_init(&ovnacts, 0);

    const struct ovnact_parse_params pp = {
        .symtab = &symtab,
        .dhcp_opts = &dhcp_opts,
        .dhcpv6_opts = &dhcpv6_opts,
        .nd_ra_opts = &nd_ra_opts,
        .n_tables = 24,
        .cur_ltable = 10,
    };
    error = ovnacts_parse_string(ds_cstr(input), &pp, &ovnacts, &prereqs);
    if (!error) {
        /* Convert the parsed representation back to a string and print it,
         * if it's different from the input. */
        struct ds ovnacts_s = DS_EMPTY_INITIALIZER;
        ovnacts_format(ovnacts.data, ovnacts.size, &ovnacts_s);
        if (strcmp(ds_cstr(input), ds_cstr(&ovnacts_s))) {
            printf("    formats as %s\n", ds_cstr(&ovnacts_s));
        }

        /* Encode the actions into OpenFlow and print. */
        const struct ovnact_encode_params ep = {
            .lookup_port = lookup_port_cb,
            .aux = &ports,
            .is_switch = true,
            .group_table = &group_table,
            .meter_table = &meter_table,

            .pipeline = OVNACT_P_INGRESS,
            .ingress_ptable = 8,
            .egress_ptable = 40,
            .output_ptable = 64,
            .mac_bind_ptable = 65,
        };
        struct ofpbuf ofpacts;
        ofpbuf_init(&ofpacts, 0);
        ovnacts_encode(ovnacts.data, ovnacts.size, &ep, &ofpacts);
        struct ds ofpacts_s = DS_EMPTY_INITIALIZER;
        struct ofpact_format_params fp = { .s = &ofpacts_s };
        ofpacts_format(ofpacts.data, ofpacts.size, &fp);
        printf("    encodes as %s\n", ds_cstr(&ofpacts_s));
        ds_destroy(&ofpacts_s);
        ofpbuf_uninit(&ofpacts);

        /* Print prerequisites if any. */
        if (prereqs) {
            struct ds prereqs_s = DS_EMPTY_INITIALIZER;
            expr_format(prereqs, &prereqs_s);
            printf("    has prereqs %s\n", ds_cstr(&prereqs_s));
            ds_destroy(&prereqs_s);
        }

        /* Now re-parse and re-format the string to verify that it's
         * round-trippable. */
        struct ofpbuf ovnacts2;
        struct expr *prereqs2;
        ofpbuf_init(&ovnacts2, 0);
        error = ovnacts_parse_string(ds_cstr(&ovnacts_s), &pp, &ovnacts2,
                                     &prereqs2);
        if (!error) {
            struct ds ovnacts2_s = DS_EMPTY_INITIALIZER;
            ovnacts_format(ovnacts2.data, ovnacts2.size, &ovnacts2_s);
            if (strcmp(ds_cstr(&ovnacts_s), ds_cstr(&ovnacts2_s))) {
                printf("    bad reformat: %s\n", ds_cstr(&ovnacts2_s));
                ok = false;
            }
            ds_destroy(&ovnacts2_s);
        } else {
            printf("    reparse error: %s\n", error);
            free(error);
            ok = false;
        }
        expr_destroy(prereqs2);

        ovnacts_free(ovnacts2.data, ovnacts2.size);
        ofpbuf_uninit(&ovnacts2);
        ds_destroy(&ovnacts_s);
    } else {
        printf("    %s\n", error);
        free(error);
    }

    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);

    simap_destroy(&ports);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    dhcp_opts_destroy(&dhcp_opts);
    dhcp_opts_destroy(&dhcpv6_opts);
    nd_ra_opts_destroy(&nd_ra_opts);
}

static void test_parse_expr(struct ds *input, int steps)
{
    struct shash symtab;
    struct shash addr_sets;
    struct shash port_groups;
    struct simap ports;
    struct expr *expr;
    char *error;

    create_symtab(&symtab);
    create_addr_sets(&addr_sets);
    create_port_groups(&port_groups);

    simap_init(&ports);
    simap_put(&ports, "eth0", 5);
    simap_put(&ports, "eth1", 6);
    simap_put(&ports, "LOCAL", ofp_to_u16(OFPP_LOCAL));
    simap_put(&ports, "lsp1", 0x11);
    simap_put(&ports, "lsp2", 0x12);
    simap_put(&ports, "lsp3", 0x13);

    expr = expr_parse_string(ds_cstr(input), &symtab, &addr_sets,
                             &port_groups, &error);
    if (!error && steps > 0) {
        expr = expr_annotate(expr, &symtab, &error);
    }
    if (!error) {
        if (steps > 1) {
            expr = expr_simplify(expr, is_chassis_resident_cb, &ports);
        }
        if (steps > 2) {
            expr = expr_normalize(expr);
            ovs_assert(expr_is_normalized(expr));
        }
    }
    if (!error) {
        if (steps > 3) {
            struct hmap matches;

            expr_to_matches(expr, lookup_port_cb, &ports, &matches);
            expr_matches_print(&matches, stdout);
            expr_matches_destroy(&matches);
        } else {
            struct ds output = DS_EMPTY_INITIALIZER;
            expr_format(expr, &output);
            puts(ds_cstr(&output));
            ds_destroy(&output);
        }
    } else {
        puts(error);
        free(error);
    }
    expr_destroy(expr);
    simap_destroy(&ports);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    expr_const_sets_destroy(&addr_sets);
    shash_destroy(&addr_sets);
    expr_const_sets_destroy(&port_groups);
    shash_destroy(&port_groups);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ds input;

    /* Bail out if we cannot construct at least a 1 char string. */
    if ((size < 2) || (data[size-1] != '\0')) {
        return 0;
    }

    /* Disable logging to avoid write to disk. */
    static bool isInit = false;
    if (!isInit) {
        vlog_set_verbosity("off");
        isInit = true;
    }

    ds_init(&input);
    ds_put_cstr(&input, (const char *)data);
    /* Parse expr. */
    test_parse_expr(&input, 0);
    /* Annotate expr. */
    test_parse_expr(&input, 1);
    /* Simplify expr. */
    test_parse_expr(&input, 2);
    /* Normalize expr. */
    test_parse_expr(&input, 3);
    /* Expr to flows. */
    test_parse_expr(&input, 4);
    /* Parse actions. */
    test_parse_actions(&input); 
    ds_destroy(&input);
    return 0;
}
