#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_calloc    calloc
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif


#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include "mbedtls/ssl_ticket.h"

#include <string>

/* Size of memory to be allocated for the heap, when using the library's memory
 * management and MBEDTLS_MEMORY_BUFFER_ALLOC_C is enabled. */
#define MEMORY_HEAP_SIZE        120000

#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         "4433"
#define DFL_RESPONSE_SIZE       -1
#define DFL_DEBUG_LEVEL         0
#define DFL_NBIO                0
#define DFL_EVENT               0
#define DFL_READ_TIMEOUT        0
#define DFL_CA_FILE             ""
#define DFL_CA_PATH             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_CRT_FILE2           ""
#define DFL_KEY_FILE2           ""
#define DFL_ASYNC_OPERATIONS    "-"
#define DFL_ASYNC_PRIVATE_DELAY1 ( -1 )
#define DFL_ASYNC_PRIVATE_DELAY2 ( -1 )
#define DFL_ASYNC_PRIVATE_ERROR  ( 0 )
#define DFL_PSK                 ""
#define DFL_PSK_IDENTITY        "Client_identity"
#define DFL_ECJPAKE_PW          NULL
#define DFL_PSK_LIST            NULL
#define DFL_FORCE_CIPHER        0
#define DFL_VERSION_SUITES      NULL
#define DFL_RENEGOTIATION       MBEDTLS_SSL_RENEGOTIATION_DISABLED
#define DFL_ALLOW_LEGACY        -2
#define DFL_RENEGOTIATE         0
#define DFL_RENEGO_DELAY        -2
#define DFL_RENEGO_PERIOD       ( (uint64_t)-1 )
#define DFL_EXCHANGES           1
#define DFL_MIN_VERSION         -1
#define DFL_MAX_VERSION         -1
#define DFL_ARC4                -1
#define DFL_SHA1                -1
#define DFL_AUTH_MODE           -1
#define DFL_CERT_REQ_CA_LIST    MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED
#define DFL_MFL_CODE            MBEDTLS_SSL_MAX_FRAG_LEN_NONE
#define DFL_TRUNC_HMAC          -1
#define DFL_TICKETS             MBEDTLS_SSL_SESSION_TICKETS_ENABLED
#define DFL_TICKET_TIMEOUT      86400
#define DFL_CACHE_MAX           -1
#define DFL_CACHE_TIMEOUT       -1
#define DFL_SNI                 NULL
#define DFL_ALPN_STRING         NULL
#define DFL_CURVES              NULL
#define DFL_DHM_FILE            NULL
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_STREAM
#define DFL_COOKIES             1
#define DFL_ANTI_REPLAY         -1
#define DFL_HS_TO_MIN           0
#define DFL_HS_TO_MAX           0
#define DFL_DTLS_MTU            -1
#define DFL_BADMAC_LIMIT        -1
#define DFL_DGRAM_PACKING        1
#define DFL_EXTENDED_MS         -1
#define DFL_ETM                 -1

#define LONG_RESPONSE "<p>01-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n" \
    "02-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "03-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "04-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "05-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "06-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "07-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah</p>\r\n"

/* Uncomment LONG_RESPONSE at the end of HTTP_RESPONSE to test sending longer
 * packets (for fragmentation purposes) */
#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n" // LONG_RESPONSE

/*
 * Size of the basic I/O buffer. Able to hold our default response.
 *
 * You will need to adapt the mbedtls_ssl_get_bytes_avail() test in ssl-opt.sh
 * if you change this value to something outside the range <= 100 or > 500
 */
#define DFL_IO_BUF_LEN      200

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "                        use \"none\" to skip loading any top-level CAs.\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded) (overrides ca_file)\n" \
    "                        use \"none\" to skip loading any top-level CAs.\n" \
    "    crt_file=%%s         Your own cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: see note after key_file2\n" \
    "    key_file=%%s         default: see note after key_file2\n" \
    "    crt_file2=%%s        Your second cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: see note after key_file2\n" \
    "    key_file2=%%s        default: see note below\n" \
    "                        note: if neither crt_file/key_file nor crt_file2/key_file2 are used,\n" \
    "                              preloaded certificate(s) and key(s) are used if available\n" \
    "    dhm_file=%%s        File containing Diffie-Hellman parameters\n" \
    "                       default: preloaded parameters\n"
#else
#define USAGE_IO \
    "\n"                                                    \
    "    No file operations available (MBEDTLS_FS_IO not defined)\n" \
    "\n"
#endif /* MBEDTLS_FS_IO */
#else
#define USAGE_IO ""
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
#define USAGE_SSL_ASYNC \
    "    async_operations=%%c...   d=decrypt, s=sign (default: -=off)\n" \
    "    async_private_delay1=%%d  Asynchronous delay for key_file or preloaded key\n" \
    "    async_private_delay2=%%d  Asynchronous delay for key_file2 and sni\n" \
    "                              default: -1 (not asynchronous)\n" \
    "    async_private_error=%%d   Async callback error injection (default=0=none,\n" \
    "                              1=start, 2=cancel, 3=resume, negative=first time only)"
#else
#define USAGE_SSL_ASYNC ""
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
#define USAGE_PSK                                                       \
    "    psk=%%s              default: \"\" (in hex, without 0x)\n"     \
    "    psk_list=%%s         default: \"\"\n"                          \
    "                          A list of (PSK identity, PSK value) pairs.\n" \
    "                          The PSK values are in hex, without 0x.\n" \
    "                          id1,psk1[,id2,psk2[,...]]\n"             \
    "    psk_identity=%%s     default: \"Client_identity\"\n"
#else
#define USAGE_PSK ""
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#define USAGE_TICKETS                                       \
    "    tickets=%%d          default: 1 (enabled)\n"       \
    "    ticket_timeout=%%d   default: 86400 (one day)\n"
#else
#define USAGE_TICKETS ""
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_CACHE_C)
#define USAGE_CACHE                                             \
    "    cache_max=%%d        default: cache default (50)\n"    \
    "    cache_timeout=%%d    default: cache default (1d)\n"
#else
#define USAGE_CACHE ""
#endif /* MBEDTLS_SSL_CACHE_C */

#if defined(SNI_OPTION)
#if defined(MBEDTLS_X509_CRL_PARSE_C)
#define SNI_CRL              ",crl"
#else
#define SNI_CRL              ""
#endif

#define USAGE_SNI                                                           \
    "    sni=%%s              name1,cert1,key1,ca1" SNI_CRL ",auth1[,...]\n"  \
    "                        default: disabled\n"
#else
#define USAGE_SNI ""
#endif /* SNI_OPTION */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
    "    max_frag_len=%%d     default: 16384 (tls default)\n"   \
    "                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
#define USAGE_TRUNC_HMAC \
    "    trunc_hmac=%%d       default: library default\n"
#else
#define USAGE_TRUNC_HMAC ""
#endif

#if defined(MBEDTLS_SSL_ALPN)
#define USAGE_ALPN \
    "    alpn=%%s             default: \"\" (disabled)\n"   \
    "                        example: spdy/1,http/1.1\n"
#else
#define USAGE_ALPN ""
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
#define USAGE_COOKIES \
    "    cookies=0/1/-1      default: 1 (enabled)\n"        \
    "                        0: disabled, -1: library default (broken)\n"
#else
#define USAGE_COOKIES ""
#endif

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
#define USAGE_ANTI_REPLAY \
    "    anti_replay=0/1     default: (library default: enabled)\n"
#else
#define USAGE_ANTI_REPLAY ""
#endif

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
#define USAGE_BADMAC_LIMIT \
    "    badmac_limit=%%d     default: (library default: disabled)\n"
#else
#define USAGE_BADMAC_LIMIT ""
#endif

#define USAGE_DTLS ""

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
#define USAGE_EMS \
    "    extended_ms=0/1     default: (library default: on)\n"
#else
#define USAGE_EMS ""
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#define USAGE_ETM \
    "    etm=0/1             default: (library default: on)\n"
#else
#define USAGE_ETM ""
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
#define USAGE_RENEGO \
    "    renegotiation=%%d    default: 0 (disabled)\n"      \
    "    renegotiate=%%d      default: 0 (disabled)\n"      \
    "    renego_delay=%%d     default: -2 (library default)\n" \
    "    renego_period=%%d    default: (2^64 - 1 for TLS, 2^48 - 1 for DTLS)\n"
#else
#define USAGE_RENEGO ""
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#define USAGE_ECJPAKE \
    "    ecjpake_pw=%%s       default: none (disabled)\n"
#else
#define USAGE_ECJPAKE ""
#endif

#if defined(MBEDTLS_ECP_C)
#define USAGE_CURVES \
    "    curves=a,b,c,d      default: \"default\" (library default)\n"  \
    "                        example: \"secp521r1,brainpoolP512r1\"\n"  \
    "                        - use \"none\" for empty list\n"           \
    "                        - see mbedtls_ecp_curve_list()\n"          \
    "                          for acceptable curve names\n"
#else
#define USAGE_CURVES ""
#endif

#define USAGE \
    "\n usage: ssl_server2 param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_addr=%%s      default: (all interfaces)\n"  \
    "    server_port=%%d      default: 4433\n"              \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    "    buffer_size=%%d      default: 200 \n" \
    "                         (minimum: 1, max: 16385)\n" \
    "    response_size=%%d    default: about 152 (basic response)\n" \
    "                          (minimum: 0, max: 16384)\n" \
    "                          increases buffer_size if bigger\n"\
    "    nbio=%%d             default: 0 (blocking I/O)\n"  \
    "                        options: 1 (non-blocking), 2 (added delays)\n" \
    "    event=%%d            default: 0 (loop)\n"                            \
    "                        options: 1 (level-triggered, implies nbio=1),\n" \
    "    read_timeout=%%d     default: 0 ms (no timeout)\n"    \
    "\n"                                                    \
    USAGE_DTLS                                              \
    USAGE_COOKIES                                           \
    USAGE_ANTI_REPLAY                                       \
    USAGE_BADMAC_LIMIT                                      \
    "\n"                                                    \
    "    auth_mode=%%s        default: (library default: none)\n"      \
    "                        options: none, optional, required\n" \
    "    cert_req_ca_list=%%d default: 1 (send ca list)\n"  \
    "                        options: 1 (send ca list), 0 (don't send)\n" \
    USAGE_IO                                                \
    USAGE_SSL_ASYNC                                         \
    USAGE_SNI                                               \
    "\n"                                                    \
    USAGE_PSK                                               \
    USAGE_ECJPAKE                                           \
    "\n"                                                    \
    "    allow_legacy=%%d     default: (library default: no)\n"      \
    USAGE_RENEGO                                            \
    "    exchanges=%%d        default: 1\n"                 \
    "\n"                                                    \
    USAGE_TICKETS                                           \
    USAGE_CACHE                                             \
    USAGE_MAX_FRAG_LEN                                      \
    USAGE_TRUNC_HMAC                                        \
    USAGE_ALPN                                              \
    USAGE_EMS                                               \
    USAGE_ETM                                               \
    USAGE_CURVES                                            \
    "\n"                                                    \
    "    arc4=%%d             default: (library default: 0)\n" \
    "    allow_sha1=%%d       default: 0\n"                             \
    "    min_version=%%s      default: (library default: tls1)\n"       \
    "    max_version=%%s      default: (library default: tls1_2)\n"     \
    "    force_version=%%s    default: \"\" (none)\n"       \
    "                        options: ssl3, tls1, tls1_1, tls1_2, dtls1, dtls1_2\n" \
    "\n"                                                                \
    "    version_suites=a,b,c,d      per-version ciphersuites\n"        \
    "                                in order from ssl3 to tls1_2\n"    \
    "                                default: all enabled\n"            \
    "    force_ciphersuite=<name>    default: all enabled\n"            \
    "    query_config=<name>         return 0 if the specified\n"       \
    "                                configuration macro is defined and 1\n"  \
    "                                otherwise. The expansion of the macro\n" \
    "                                is printed if it is defined\n"     \
    " acceptable ciphersuite names:\n"

#define ALPN_LIST_SIZE  10
#define CURVE_LIST_SIZE 20

#define PUT_UINT64_BE(out_be,in_le,i)                                   \
{                                                                       \
    (out_be)[(i) + 0] = (unsigned char)( ( (in_le) >> 56 ) & 0xFF );    \
    (out_be)[(i) + 1] = (unsigned char)( ( (in_le) >> 48 ) & 0xFF );    \
    (out_be)[(i) + 2] = (unsigned char)( ( (in_le) >> 40 ) & 0xFF );    \
    (out_be)[(i) + 3] = (unsigned char)( ( (in_le) >> 32 ) & 0xFF );    \
    (out_be)[(i) + 4] = (unsigned char)( ( (in_le) >> 24 ) & 0xFF );    \
    (out_be)[(i) + 5] = (unsigned char)( ( (in_le) >> 16 ) & 0xFF );    \
    (out_be)[(i) + 6] = (unsigned char)( ( (in_le) >> 8  ) & 0xFF );    \
    (out_be)[(i) + 7] = (unsigned char)( ( (in_le) >> 0  ) & 0xFF );    \
}


/*
 * global options
 */
struct options
{
    const char *server_addr;    /* address on which the ssl service runs    */
    uint16_t server_port;    /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    int event;                  /* loop or event-driven IO? level or edge triggered? */
    uint32_t read_timeout;      /* timeout on mbedtls_ssl_read() in milliseconds    */
    int response_size;          /* pad response with header to requested size */
    uint16_t buffer_size;       /* IO buffer size */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *crt_file;       /* the file with the server certificate     */
    const char *key_file;       /* the file with the server key             */
    const char *crt_file2;      /* the file with the 2nd server certificate */
    const char *key_file2;      /* the file with the 2nd server key         */
    const char *async_operations; /* supported SSL asynchronous operations  */
    int async_private_delay1;   /* number of times f_async_resume needs to be called for key 1, or -1 for no async */
    int async_private_delay2;   /* number of times f_async_resume needs to be called for key 2, or -1 for no async */
    int async_private_error;    /* inject error in async private callback */
    const char *psk;            /* the pre-shared key                       */
    const char *psk_identity;   /* the pre-shared key identity              */
    char *psk_list;             /* list of PSK id/key pairs for callback    */
    const char *ecjpake_pw;     /* the EC J-PAKE password                   */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    const char *version_suites; /* per-version ciphersuites                 */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
    int renegotiate;            /* attempt renegotiation?                   */
    int renego_delay;           /* delay before enforcing renegotiation     */
    uint64_t renego_period;     /* period for automatic renegotiation       */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int arc4;                   /* flag for arc4 suites support             */
    int allow_sha1;             /* flag for SHA-1 support                   */
    int auth_mode;              /* verify mode for connection               */
    int cert_req_ca_list;       /* should we send the CA list?              */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int trunc_hmac;             /* accept truncated hmac?                   */
    int tickets;                /* enable / disable session tickets         */
    int ticket_timeout;         /* session ticket lifetime                  */
    int cache_max;              /* max number of session cache entries      */
    int cache_timeout;          /* expiration delay of session cache entries */
    char *sni;                  /* string describing sni information        */
    const char *curves;         /* list of supported elliptic curves        */
    const char *alpn_string;    /* ALPN supported protocols                 */
    const char *dhm_file;       /* the file with the DH parameters          */
    int extended_ms;            /* allow negotiation of extended MS?        */
    int etm;                    /* allow negotiation of encrypt-then-MAC?   */
    int transport;              /* TLS or DTLS?                             */
    int cookies;                /* Use cookies for DTLS? -1 to break them   */
    int anti_replay;            /* Use anti-replay for DTLS? -1 for default */
    uint32_t hs_to_min;         /* Initial value of DTLS handshake timer    */
    uint32_t hs_to_max;         /* Max value of DTLS handshake timer        */
    int dtls_mtu;               /* UDP Maximum tranport unit for DTLS       */
    int dgram_packing;          /* allow/forbid datagram packing            */
    int badmac_limit;           /* Limit of records with bad MAC            */
} ;

class MbedTlsParams {
public:
	MbedTlsParams(int fd){
		client_fd.fd = fd;	
		init_ssl_server();
	}
    ~MbedTlsParams();
	mbedtls_x509_crt_profile crt_profile_for_test = mbedtls_x509_crt_profile_default;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;

	uint32_t flags;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt srvcert;
	mbedtls_pk_context pkey;
	mbedtls_x509_crt srvcert2;
	mbedtls_pk_context pkey2;
	int key_cert_init = 0, key_cert_init2 = 0;
	mbedtls_ssl_ticket_context ticket_ctx;

    mbedtls_net_context client_fd;
public:
    int init_ssl_server();
    int do_handshake();
    int ssl_recv(uint8_t* buf, int& len);
    int ssl_write(const std::string& packet);
    int ssl_close();
};

int ssl_listen(uint16_t ssl_server_port, int& ssl_listen_fd);

#endif
