#include <config.h>
#include "fuzzer.h"
#include "nx-match.h"
#include "ofp-version-opt.h"
#include "ofproto/ofproto.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

static void
ofctl_parse_nxm(bool oxm, enum ofp_version version, const char *input)
{
    struct ofpbuf nx_match;
    struct match match;
    ovs_be64 cookie, cookie_mask;
    enum ofperr error;
    int match_len;

    /* Convert string to nx_match. */
    ofpbuf_init(&nx_match, 0);
    if (oxm) {
        match_len = oxm_match_from_string(input, &nx_match);
    } else {
        match_len = nx_match_from_string(input, &nx_match);
    }

    /* Convert nx_match to match. */
    if (oxm) {
        error = oxm_pull_match(&nx_match, false, NULL, NULL, &match);
    } else {
        error = nx_pull_match(&nx_match, match_len, &match, &cookie,
                              &cookie_mask, false, NULL, NULL);
    }

    if (!error) {
        char *out;

        /* Convert match back to nx_match. */
        ofpbuf_uninit(&nx_match);
        ofpbuf_init(&nx_match, 0);
        if (oxm) {
            match_len = oxm_put_match(&nx_match, &match, version);
            out = oxm_match_to_string(&nx_match, match_len);
        } else {
            match_len = nx_put_match(&nx_match, &match,
                                     cookie, cookie_mask);
            out = nx_match_to_string(nx_match.data, match_len);
        }

        puts(out);
        free(out);

        ovs_hex_dump(stdout, nx_match.data, nx_match.size, 0, false);
    } else {
        printf("nx_pull_match() returned error %s\n",
               ofperr_get_name(error));
    }

    ofpbuf_uninit(&nx_match);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Bail out if we cannot construct at least a 1 char string.
     * Reserve 1 byte to decide OFP version and oxm/nxm.
     */
    const char *stream = data;
    if (size < 3 || stream[size - 1] != '\0' || strchr(stream, '\n')) {
        return 0;
    }

    /* Disable logging to avoid write to disk. */
    static bool isInit = false;
    if (!isInit) {
        vlog_set_verbosity("off");
        isInit = true;
    }

    /* Decide test parameters using first byte of fuzzed input. */
    bool oxm = stream[0] % 2;
    enum ofp_version ver = (stream[0] % 7) + 1;

    /* Fuzz extended match parsing. */
    const char *input = stream[1];
    ofctl_parse_nxm(oxm, ver, input);

    return 0;
}