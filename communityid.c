/* ---- Generic Community ID codebase, based on GLib & GCrypt ------------------
 *
 * The code between here and the corresponding end comment below
 * provides a reusable implementation of the Community ID. To avoid
 * dealing imperfectly with low-level implementation details, it
 * assumes GLib and GCrypt are available. Adaptation to other data
 * types should be straightforward.
 *
 * Version 1.0
 *
 * For updates or feedback please visit:
 * https://github.com/corelight/c-community-id
 *
 * Copyright (c) 2017-2020 by Corelight, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 * (3) Neither the name of Corelight, Inc, nor the names of contributors
 *     may be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* 8-bit IP protocol numbers, likely redundant with similar
 * definitions in the surrounding project, but having these here keeps
 * the Community ID code self-contained.
 */
#define CID_PROTO_ICMP 1
#define CID_PROTO_IP 4
#define CID_PROTO_TCP 6
#define CID_PROTO_UDP 17
#define CID_PROTO_IPV6 41
#define CID_PROTO_ICMPV6 58
#define CID_PROTO_SCTP 132

/* Similarly, ICMP type numbers, to implement flow-like treatment of
 * the ICMPs via type & code values.
 */
#define CID_ICMP_ECHO_REPLY 0
#define CID_ICMP_ECHO 8
#define CID_ICMP_RTR_ADVERT 9
#define CID_ICMP_RTR_SOLICIT 10
#define CID_ICMP_TSTAMP 13
#define CID_ICMP_TSTAMP_REPLY 14
#define CID_ICMP_INFO 15
#define CID_ICMP_INFO_REPLY 16
#define CID_ICMP_MASK 17
#define CID_ICMP_MASK_REPLY 18

#define CID_ICMPV6_ECHO_REQUEST 128
#define CID_ICMPV6_ECHO_REPLY 129
#define CID_ICMPV6_MLD_LISTENER_QUERY 130
#define CID_ICMPV6_MLD_LISTENER_REPORT 131
#define CID_ICMPV6_ND_ROUTER_SOLICIT 133
#define CID_ICMPV6_ND_ROUTER_ADVERT 134
#define CID_ICMPV6_ND_NEIGHBOR_SOLICIT 135
#define CID_ICMPV6_ND_NEIGHBOR_ADVERT 136
#define CID_ICMPV6_WRU_REQUEST 139
#define CID_ICMPV6_WRU_REPLY 140
#define CID_ICMPV6_HAAD_REQUEST 144
#define CID_ICMPV6_HAAD_REPLY 145

/* There's currently only a v1, so we hardwire its prefix string. */
#define CID_VERSION_PREFIX "1:"

/* Largest IP address size currently supported, to simplify buffer
 * allocations in C90-compliant codebases.
 */
#define CID_ADDR_LEN_MAX 16

/* Set to 1 for debugging output to stderr. */
#define CID_DEBUG 0

typedef struct _communityid_cfg_t {
    gboolean cfg_do_base64;
    guint16 cfg_seed;
} communityid_cfg_t;

#if CID_DEBUG
static void communityid_sha1_dbg(const gchar *msg, const void* data, gsize len)
{
    gchar *buf = (gchar*) g_malloc(len*2 + 1);
    gchar *ptr = buf;
    gsize i;

    for (i = 0; i < len; i++, ptr += 2) {
        g_snprintf(ptr, 3, "%02x", ((guchar*)data)[i]);
    }

    fprintf(stderr, "Community ID dbg [%s]: %s\n", msg, buf);
    g_free(buf);
}
#define COMMUNITYID_SHA1_DBG(...) communityid_sha1_dbg(__VA_ARGS__)
#else
#define COMMUNITYID_SHA1_DBG(...)
#endif

/* Helper function to determine whether a flow tuple is ordered
 * correctly or needs flipping for abstracting flow directionality.
 */
static gboolean communityid_tuple_lt(guint8 addr_len,
                                     const guchar *saddr, const guchar  *daddr,
                                     const guint16 *sport, const guint16 *dport)
{
    int addrcmp = memcmp(saddr, daddr, addr_len);
    int ports_lt = (sport != NULL && dport != NULL) ? *sport < *dport : TRUE;
    return addrcmp < 0 || (addrcmp == 0 && ports_lt);
}

/* Main Community ID computation routine. Arguments:
 *
 * - cfg: a pointer to a communityid_cfg_t instance with configuration
 *   information.
 *
 * - proto: an 8-bit unsigned value representing the IP protocol
 *   number of the transport layer (or equivalent) protocol.
 *
 * - addr_len: the length in octets of the network-layer addresses we
 *   use. Must be either 4 (for IPv4) or 16 (for IPv6).
 *
 * - saddr/daddr: pointers to the network-layer source/destination
 *   address, in NBO.
 *
 * - sport/dport: pointers to the transport-layer 16-bit port numbers,
 *   in NBO. These may be NULL pointers to signal that port numbers
 *   aren't available for the flow.
 *
 * - result: the address of a result pointer that will point at a
 *   newly allocated string containing the computed ID value upon
 *   return from the function. Callers take ownership of the allocated
 *   string and need to free it when finished.
 *
 * Return value: a Boolean, TRUE if the computation was successful and
 * FALSE otherwise. The function modifies the result pointer only when
 * the return value is TRUE.
 */
static gboolean communityid_calc(communityid_cfg_t *cfg, guint8 proto,
                                 guint8 addr_len, const guchar *saddr, const guchar *daddr,
                                 const guint16 *sport, const guint16 *dport,
                                 gchar **result)
{
    gboolean is_one_way = FALSE;
    guint8 padding = 0;
    guint16 seed_final = 0;
    gcry_md_hd_t sha1;
    guchar *sha1_buf = NULL;
    gsize sha1_buf_len = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
    guint16 sport_final, dport_final;

    g_return_val_if_fail(cfg != NULL, FALSE);
    g_return_val_if_fail(result != NULL, FALSE);
    g_return_val_if_fail(addr_len == 4 || addr_len == 16, FALSE);
    g_return_val_if_fail(saddr != NULL && daddr != NULL, FALSE);

    if (sport != NULL && dport != NULL) {
        sport_final = *sport;
        dport_final = *dport;

        /* Sort out directionality of this packet in the flow. For
         * regular bidirectional traffic we resort this by ordering
         * the flow tuple. ICMP is our corner-case; we use its type
         * and code values as port equivalents, and expand them when
         * feasible to provide directionality. This is based on Zeek's
         * internal model of ICMP traffic.
         */
        switch (proto) {
        case CID_PROTO_ICMP:
            {
                /* Get ports from network byte order: */
                sport_final = GUINT16_FROM_BE(sport_final);
                dport_final = GUINT16_FROM_BE(dport_final);

                switch (sport_final) {
                case CID_ICMP_ECHO:
                    dport_final = CID_ICMP_ECHO_REPLY;
                    break;
                case CID_ICMP_ECHO_REPLY:
                    dport_final = CID_ICMP_ECHO;
                    break;
                case CID_ICMP_TSTAMP:
                    dport_final = CID_ICMP_TSTAMP_REPLY;
                    break;
                case CID_ICMP_TSTAMP_REPLY:
                    dport_final = CID_ICMP_TSTAMP;
                    break;
                case CID_ICMP_INFO:
                    dport_final = CID_ICMP_INFO_REPLY;
                    break;
                case CID_ICMP_INFO_REPLY:
                    dport_final = CID_ICMP_INFO;
                    break;
                case CID_ICMP_RTR_SOLICIT:
                    dport_final = CID_ICMP_RTR_ADVERT;
                    break;
                case CID_ICMP_RTR_ADVERT:
                    dport_final = CID_ICMP_RTR_SOLICIT;
                    break;
                case CID_ICMP_MASK:
                    dport_final = CID_ICMP_MASK_REPLY;
                    break;
                case CID_ICMP_MASK_REPLY:
                    dport_final = CID_ICMP_MASK;
                    break;
                default:
                    is_one_way = TRUE;
                }

                /* And back to NBO: */
                sport_final = GUINT16_TO_BE(sport_final);
                dport_final = GUINT16_TO_BE(dport_final);
            }
            break;
        case CID_PROTO_ICMPV6:
            {
                sport_final = GUINT16_FROM_BE(sport_final);
                dport_final = GUINT16_FROM_BE(dport_final);

                switch (sport_final) {
                case CID_ICMPV6_ECHO_REQUEST:
                    dport_final = CID_ICMPV6_ECHO_REPLY;
                    break;
                case CID_ICMPV6_ECHO_REPLY:
                    dport_final = CID_ICMPV6_ECHO_REQUEST;
                    break;
                case CID_ICMPV6_MLD_LISTENER_QUERY:
                    dport_final = CID_ICMPV6_MLD_LISTENER_REPORT;
                    break;
                case CID_ICMPV6_MLD_LISTENER_REPORT:
                    dport_final = CID_ICMPV6_MLD_LISTENER_QUERY;
                    break;
                case CID_ICMPV6_ND_ROUTER_SOLICIT:
                    dport_final = CID_ICMPV6_ND_ROUTER_ADVERT;
                    break;
                case CID_ICMPV6_ND_ROUTER_ADVERT:
                    dport_final = CID_ICMPV6_ND_ROUTER_SOLICIT;
                    break;
                case CID_ICMPV6_ND_NEIGHBOR_SOLICIT:
                    dport_final = CID_ICMPV6_ND_NEIGHBOR_ADVERT;
                    break;
                case CID_ICMPV6_ND_NEIGHBOR_ADVERT:
                    dport_final = CID_ICMPV6_ND_NEIGHBOR_SOLICIT;
                    break;
                case CID_ICMPV6_WRU_REQUEST:
                    dport_final = CID_ICMPV6_WRU_REPLY;
                    break;
                case CID_ICMPV6_WRU_REPLY:
                    dport_final = CID_ICMPV6_WRU_REQUEST;
                    break;
                case CID_ICMPV6_HAAD_REQUEST:
                    dport_final = CID_ICMPV6_HAAD_REPLY;
                    break;
                case CID_ICMPV6_HAAD_REPLY:
                    dport_final = CID_ICMPV6_HAAD_REQUEST;
                    break;
                default:
                    is_one_way = TRUE;
                }

                sport_final = GUINT16_TO_BE(sport_final);
                dport_final = GUINT16_TO_BE(dport_final);
            }
        default:
            ;
        }

        sport = &sport_final;
        dport = &dport_final;
    }

    if (is_one_way || communityid_tuple_lt(addr_len, saddr, daddr,
                                           sport, dport)) {
        /* Ordered correctly, no need to flip. */
    } else {
        /* Need to flip endpoints for consistent hashing. */
        const guchar *tmp_addr = saddr;
        saddr = daddr;
        daddr = tmp_addr;

        if (sport != NULL && dport != NULL) {
            const guint16 *tmp_port = sport;
            sport = dport;
            dport = tmp_port;
        }
    }

    seed_final = GUINT16_TO_BE(cfg->cfg_seed);

    /* SHA-1 computation */

    if (gcry_md_open(&sha1, GCRY_MD_SHA1, 0))
        return FALSE;

    COMMUNITYID_SHA1_DBG("seed", &seed_final, 2);
    gcry_md_write(sha1, &seed_final, 2);

    COMMUNITYID_SHA1_DBG("saddr", saddr, addr_len);
    gcry_md_write(sha1, saddr, addr_len);

    COMMUNITYID_SHA1_DBG("daddr", daddr, addr_len);
    gcry_md_write(sha1, daddr, addr_len);

    COMMUNITYID_SHA1_DBG("proto", &proto, 1);
    gcry_md_write(sha1, &proto, 1);

    COMMUNITYID_SHA1_DBG("padding", &padding, 1);
    gcry_md_write(sha1, &padding, 1);

    if (sport != NULL && dport != NULL) {
        COMMUNITYID_SHA1_DBG("sport", sport, 2);
        gcry_md_write(sha1, sport, 2);

        COMMUNITYID_SHA1_DBG("dport", dport, 2);
        gcry_md_write(sha1, dport, 2);
    }

    sha1_buf = (guchar*) g_malloc(sha1_buf_len);
    memcpy(sha1_buf, gcry_md_read(sha1, 0), sha1_buf_len);
    gcry_md_close(sha1);

    if (cfg->cfg_do_base64) {
        gchar *str = g_base64_encode(sha1_buf, sha1_buf_len);
        gsize len = strlen(CID_VERSION_PREFIX) + strlen(str) + 1;

        *result = (gchar*) g_malloc(len);
        g_snprintf(*result, len, "%s%s", CID_VERSION_PREFIX, str);
        g_free(str);
    } else {
        /* Convert binary SHA-1 to ASCII representation.
         * 2 hex digits for every byte + 1 for trailing \0:
         */
        gchar *ptr;
        gsize i;

        *result = (gchar*) g_malloc(strlen(CID_VERSION_PREFIX) + sha1_buf_len*2 + 1);
        memcpy(*result, CID_VERSION_PREFIX, strlen(CID_VERSION_PREFIX));
        ptr = *result + strlen(CID_VERSION_PREFIX);
        for (i = 0; i < sha1_buf_len; i++, ptr += 2) {
            g_snprintf(ptr, 3, "%02x", sha1_buf[i]);
        }
    }

    g_free(sha1_buf);

    return TRUE;
}

/* ---- End of generic Community ID codebase ----------------------------------- */
