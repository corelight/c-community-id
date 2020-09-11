/* Example code for use of the communityid.c module. This provides a
 * simple command-line version for ocmputing ID values. This code is
 * simplistic and assumes benign command-line input values.
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <glib.h>
#include <gcrypt.h>

/* In practice you'd most likely paste the sources directly into
 * yours. We include them here mainly to demonstrate its use.
 */
#include "communityid.c"

void usage(void) {
    fprintf(stderr, "Usage: community-id [-h] [--seed NUM] [--no-base64] ...\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Community ID calculator\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "This calculator prints the Community ID value for a given tuple\n");
    fprintf(stderr, "to stdout. It supports the following format for the tuple:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  [protocol] [src address] [dst address] [src port] [dst port]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "The protocol is either a numeric IP protocol number, or one of\n");
    fprintf(stderr, "the constants \"icmp\", \"icmp6\", \"tcp\", \"udp\", or \"sctp\".\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "positional arguments:\n");
    fprintf(stderr, "  flowtuple    Flow tuple, in the above order\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "optional arguments:\n");
    fprintf(stderr, "-h, --help   show this help message and exit\n");
    fprintf(stderr, "--seed NUM   Seed value for hash operations\n");
    fprintf(stderr, "--no-base64  Don't base64-encode the SHA1 binary value\n");
}

int main(int argc, char **argv) {
    communityid_cfg_t cfg;
    guint8 proto;
    guchar saddr[16], daddr[16];
    guint16 sport, dport;
    gchar *cid = NULL;
    gboolean saddr_is_v6, daddr_is_v6;
    guint8 addr_len = 0;

    cfg.cfg_do_base64 = TRUE;
    cfg.cfg_seed = 0;

    while (TRUE) {
        int c, option_index = 0;
        static struct option long_options[] = {
            {"help", no_argument, 0, 'h'},
            {"no-base64", no_argument, 0, 'n'},
            {"seed", required_argument, 0, 's'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "s:n:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage();
            return 0;
        case 'n':
            cfg.cfg_do_base64 = FALSE;
            break;
        case 's':
            cfg.cfg_seed = (guint16) atoi(optarg);
            break;
        default:
            usage();
            return 1;
        }
    }

    if (argc - optind < 5) {
        fprintf(stderr, "Please provide full flow tuple arguments.\n\n");
        usage();
        return 1;
    }

    /* Parse proto: */
    if (strcmp(argv[optind], "icmp") == 0) {
        proto = CID_PROTO_ICMP;
    } else if (strcmp(argv[optind], "icmp6") == 0) {
        proto = CID_PROTO_ICMPV6;
    } else if (strcmp(argv[optind], "tcp") == 0) {
        proto = CID_PROTO_TCP;
    } else if (strcmp(argv[optind], "udp") == 0) {
        proto = CID_PROTO_UDP;
    } else if (strcmp(argv[optind], "sctp") == 0) {
        proto = CID_PROTO_SCTP;
    } else {
        proto = atoi(argv[optind]);
    }

    optind++;

    /* Quick check: either both addresses are v4, or both are v6: */
    saddr_is_v6 = (strchr(argv[optind], ':') != NULL);
    daddr_is_v6 = (strchr(argv[optind+1], ':') != NULL);

    if ( (saddr_is_v6 && !daddr_is_v6) || (!saddr_is_v6 && daddr_is_v6) ) {
        fprintf(stderr, "Both addresses must be either IPv4, or IPv6\n");
        return 1;
    }

    /* Parse source/dest addresses: */
    if (saddr_is_v6) {
        addr_len = 16;

        if (inet_pton(AF_INET6, argv[optind], saddr) <= 0) {
            fprintf(stderr, "Invalid IPv6 src address: %s\n", argv[optind]);
            return 1;
        }
        if (inet_pton(AF_INET6, argv[optind+1], daddr) <= 0) {
            fprintf(stderr, "Invalid IPv6 dst address: %s\n", argv[optind+1]);
            return 1;
        }
    } else {
        addr_len = 4;

        if (inet_pton(AF_INET, argv[optind], saddr) <= 0) {
            fprintf(stderr, "Invalid IPv4 src address: %s\n", argv[optind]);
            return 1;
        }
        if (inet_pton(AF_INET, argv[optind+1], daddr) <= 0) {
            fprintf(stderr, "Invalid IPv4 dst address: %s\n", argv[optind+1]);
            return 1;
        }
    }

    optind += 2;

    /* Parse source port: */
    sport = g_htons(atoi(argv[optind]));

    optind++;

    /* Parse dest port: */
    dport = g_htons(atoi(argv[optind]));

    if (! communityid_calc(&cfg, proto, addr_len, saddr, daddr, &sport, &dport, &cid)) {
        fprintf(stderr, "Could not generate Community ID value\n");
        return 1;
    }

    printf("%s\n", cid);
    g_free(cid);
    return 0;
}
