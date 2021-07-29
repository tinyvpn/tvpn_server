/*
 *  SSL server with options
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include "ssl_server.h"
#include "log.h"

struct options opt;
const int BUF_SIZE = 4096*4;

int query_config( const char *config );

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: |%d| %s", basename, line, level, str );
    fflush(  (FILE *) ctx  );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
static int my_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    ret = mbedtls_net_recv( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int my_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }

    ret = mbedtls_net_send( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

/*
 * Return authmode from string, or -1 on error
 */
static int get_auth_mode( const char *s )
{
    if( strcmp( s, "none" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_NONE );
    if( strcmp( s, "optional" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_OPTIONAL );
    if( strcmp( s, "required" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_REQUIRED );

    return( -1 );
}

/*
 * Used by sni_parse and psk_parse to handle coma-separated lists
 */
#define GET_ITEM( dst )         \
    do                          \
    {                           \
        (dst) = p;              \
        while( *p != ',' )      \
            if( ++p > end )     \
                goto error;     \
        *p++ = '\0';            \
    } while( 0 )


static mbedtls_net_context listen_fd;

/* Interruption handler to ensure clean exit (for valgrind testing) */
static int received_sigterm = 0;
void term_handler( int sig )
{
    ((void) sig);
    received_sigterm = 1;
    mbedtls_net_free( &listen_fd ); /* causes mbedtls_net_accept() to abort */
//    mbedtls_net_free( &client_fd ); /* causes net_read() to abort */
}

static int ssl_sig_hashes_for_test[] = {
    MBEDTLS_MD_SHA512,
    MBEDTLS_MD_SHA384,
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA224,
    /* Allow SHA-1 as we use it extensively in tests. */
    MBEDTLS_MD_SHA1,
    MBEDTLS_MD_NONE
};

/** Return true if \p ret is a status code indicating that there is an
 * operation in progress on an SSL connection, and false if it indicates
 * success or a fatal error.
 *
 * The possible operations in progress are:
 *
 * - A read, when the SSL input buffer does not contain a full message.
 * - A write, when the SSL output buffer contains some data that has not
 *   been sent over the network yet.
 * - An asynchronous callback that has not completed yet. */
static int mbedtls_status_is_ssl_in_progress( int ret )
{
    return( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
}

/*
 * Wait for an event from the underlying transport or the timer
 * (Used in event-driven IO mode).
 */
int idle( mbedtls_net_context *fd,
          mbedtls_timing_delay_context *timer,
          int idle_reason )
{
    int ret;
    int poll_type = 0;

    if( idle_reason == MBEDTLS_ERR_SSL_WANT_WRITE )
        poll_type = MBEDTLS_NET_POLL_WRITE;
    else if( idle_reason == MBEDTLS_ERR_SSL_WANT_READ )
        poll_type = MBEDTLS_NET_POLL_READ;

    while( 1 )
    {
        /* Check if timer has expired */
        if( timer != NULL &&
            mbedtls_timing_get_delay( timer ) == 2 )
        {
            break;
        }

        /* Check if underlying transport became available */
        if( poll_type != 0 )
        {
            ret = mbedtls_net_poll( fd, poll_type, 0 );
            if( ret < 0 )
                return( ret );
            if( ret == poll_type )
                break;
        }
    }

    return( 0 );
}
int ssl_init()
{
    opt.buffer_size         = DFL_IO_BUF_LEN;
    opt.server_addr         = DFL_SERVER_ADDR;
//    opt.server_port         = ssl_server_port;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.event               = DFL_EVENT;
    opt.response_size       = DFL_RESPONSE_SIZE;
    opt.nbio                = DFL_NBIO;
    opt.read_timeout        = DFL_READ_TIMEOUT;
    opt.ca_file             = "ca/cacert.pem";
    opt.ca_path             = DFL_CA_PATH;
    opt.crt_file            = "ca/test.crt";
    opt.key_file            = "ca/test.key";
    opt.crt_file2           = DFL_CRT_FILE2;
    opt.key_file2           = DFL_KEY_FILE2;
    opt.async_operations    = DFL_ASYNC_OPERATIONS;
    opt.async_private_delay1 = DFL_ASYNC_PRIVATE_DELAY1;
    opt.async_private_delay2 = DFL_ASYNC_PRIVATE_DELAY2;
    opt.async_private_error = DFL_ASYNC_PRIVATE_ERROR;
    opt.psk                 = DFL_PSK;
    opt.psk_identity        = DFL_PSK_IDENTITY;
    opt.psk_list            = DFL_PSK_LIST;
    opt.ecjpake_pw          = DFL_ECJPAKE_PW;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.version_suites      = DFL_VERSION_SUITES;
    opt.renegotiation       = DFL_RENEGOTIATION;
    opt.allow_legacy        = DFL_ALLOW_LEGACY;
    opt.renegotiate         = DFL_RENEGOTIATE;
    opt.renego_delay        = DFL_RENEGO_DELAY;
    opt.renego_period       = DFL_RENEGO_PERIOD;
    opt.exchanges           = DFL_EXCHANGES;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.arc4                = DFL_ARC4;
    opt.allow_sha1          = DFL_SHA1;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.cert_req_ca_list    = DFL_CERT_REQ_CA_LIST;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.trunc_hmac          = DFL_TRUNC_HMAC;
    opt.tickets             = DFL_TICKETS;
    opt.ticket_timeout      = DFL_TICKET_TIMEOUT;
    opt.cache_max           = DFL_CACHE_MAX;
    opt.cache_timeout       = DFL_CACHE_TIMEOUT;
    opt.sni                 = DFL_SNI;
    opt.alpn_string         = DFL_ALPN_STRING;
    opt.curves              = DFL_CURVES;
    opt.dhm_file            = DFL_DHM_FILE;
    opt.transport           = DFL_TRANSPORT;
    opt.cookies             = DFL_COOKIES;
    opt.anti_replay         = DFL_ANTI_REPLAY;
    opt.hs_to_min           = DFL_HS_TO_MIN;
    opt.hs_to_max           = DFL_HS_TO_MAX;
    opt.dtls_mtu            = DFL_DTLS_MTU;
    opt.dgram_packing       = DFL_DGRAM_PACKING;
    opt.badmac_limit        = DFL_BADMAC_LIMIT;
    opt.extended_ms         = DFL_EXTENDED_MS;
    opt.etm                 = DFL_ETM;

}
int ssl_listen(uint16_t ssl_server_port, int& ssl_listen_fd)
{
    mbedtls_net_init( &listen_fd );
    opt.server_port         = ssl_server_port;
    ssl_init();
    
    /*
     * 2. Setup the listening TCP socket
     */
    INFO( "  . Bind on %s://%s:%d/ ...",
            opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "tcp" : "udp",
            opt.server_addr ? opt.server_addr : "*",
            opt.server_port );
    fflush( stdout );
    
    int ret;
    if( ( ret = mbedtls_net_bind( &listen_fd, opt.server_addr, std::to_string(opt.server_port).c_str(),
                          opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ?
                          MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        ERROR( " failed! mbedtls_net_bind returned -0x%x", -ret );
        return 1;
    }
    ssl_listen_fd = listen_fd.fd;
    return 0;
}
MbedTlsParams::~MbedTlsParams()
{
    INFO( "  . MbedTlsParams Cleaning up..." );
    fflush( stdout );

    mbedtls_net_free( &client_fd );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_x509_crt_free( &srvcert2 );
    mbedtls_pk_free( &pkey2 );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_ssl_ticket_free( &ticket_ctx );
    return;
}
int MbedTlsParams::init_ssl_server()
{
    int ret = 0, len, written, frags, exchanges_left;
    int version_suites[4][2];
    const char *pers = "ssl_server2";
    unsigned char client_ip[16] = { 0 };
    size_t cliip_len;

    int i;
    char *p, *q;
    const int *list;

    /*
     * Make sure memory references are valid in case we exit early.
     */
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_x509_crt_init( &srvcert2 );
    mbedtls_pk_init( &pkey2 );
    mbedtls_ssl_ticket_init( &ticket_ctx );

    /* Abort cleanly on SIGTERM and SIGINT */
    signal( SIGTERM, term_handler );
    signal( SIGINT, term_handler );


    mbedtls_debug_set_threshold( opt.debug_level );

    if( opt.force_ciphersuite[0] > 0 )
    {
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
        ciphersuite_info =
            mbedtls_ssl_ciphersuite_from_id( opt.force_ciphersuite[0] );

        if( opt.max_version != -1 &&
            ciphersuite_info->min_minor_ver > opt.max_version )
        {
            ERROR( "forced ciphersuite not allowed with this protocol version");
            ret = 2;
            goto usage;
        }
        if( opt.min_version != -1 &&
            ciphersuite_info->max_minor_ver < opt.min_version )
        {
            ERROR( "forced ciphersuite not allowed with this protocol version");
            ret = 2;
            goto usage;
        }

        /* If we select a version that's not supported by
         * this suite, then there will be no common ciphersuite... */
        if( opt.max_version == -1 ||
            opt.max_version > ciphersuite_info->max_minor_ver )
        {
            opt.max_version = ciphersuite_info->max_minor_ver;
        }
        if( opt.min_version < ciphersuite_info->min_minor_ver )
        {
            opt.min_version = ciphersuite_info->min_minor_ver;
            /* DTLS starts with TLS 1.1 */
            if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
                opt.min_version < MBEDTLS_SSL_MINOR_VERSION_2 )
                opt.min_version = MBEDTLS_SSL_MINOR_VERSION_2;
        }

        /* Enable RC4 if needed and not explicitly disabled */
        if( ciphersuite_info->cipher == MBEDTLS_CIPHER_ARC4_128 )
        {
            if( opt.arc4 == MBEDTLS_SSL_ARC4_DISABLED )
            {
                ERROR("forced RC4 ciphersuite with RC4 disabled");
                ret = 2;
                goto usage;
            }

            opt.arc4 = MBEDTLS_SSL_ARC4_ENABLED;
        }
    }

    if( opt.version_suites != NULL )
    {
        const char *name[4] = { 0 };

        /* Parse 4-element coma-separated list */
        for( i = 0, p = (char *) opt.version_suites;
             i < 4 && *p != '\0';
             i++ )
        {
            name[i] = p;

            /* Terminate the current string and move on to next one */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';
        }

        if( i != 4 )
        {
            ERROR( "too few values for version_suites");
            ret = 1;
            goto exit;
        }

        memset( version_suites, 0, sizeof( version_suites ) );

        /* Get the suites identifiers from their name */
        for( i = 0; i < 4; i++ )
        {
            version_suites[i][0] = mbedtls_ssl_get_ciphersuite_id( name[i] );

            if( version_suites[i][0] == 0 )
            {
                ERROR( "unknown ciphersuite: '%s'", name[i] );
                ret = 2;
                goto usage;
            }
        }
    }
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                       &entropy, (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        ERROR( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x", -ret );
        goto exit;
    }

    /*
     * 1.1. Load the trusted CA
     */
    DEBUG( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    if( strcmp( opt.ca_path, "none" ) == 0 ||
        strcmp( opt.ca_file, "none" ) == 0 )
    {
        ret = 0;
    }
    else
    if( strlen( opt.ca_path ) ){
        ret = mbedtls_x509_crt_parse_path( &cacert, opt.ca_path );
    } else if( strlen( opt.ca_file ) ){
        ret = mbedtls_x509_crt_parse_file( &cacert, opt.ca_file );
        INFO("load cacert ok.");
    } else {
        for( i = 0; mbedtls_test_cas[i] != NULL; i++ )
        {
            ret = mbedtls_x509_crt_parse( &cacert,
                                  (const unsigned char *) mbedtls_test_cas[i],
                                  mbedtls_test_cas_len[i] );
            if( ret != 0 )
                break;
        }
        if( ret == 0 )
        for( i = 0; mbedtls_test_cas_der[i] != NULL; i++ )
        {
            ret = mbedtls_x509_crt_parse_der( &cacert,
                         (const unsigned char *) mbedtls_test_cas_der[i],
                         mbedtls_test_cas_der_len[i] );
            if( ret != 0 )
                break;
        }
    }

    if( ret < 0 )
    {
        ERROR( " failed!  mbedtls_x509_crt_parse returned -0x%x", -ret );
        goto exit;
    }

    DEBUG( " ok (%d skipped)", ret );

    /*
     * 1.2. Load own certificate and private key
     */
    DEBUG( "  . Loading the server cert. and key..." );

    if( strlen( opt.crt_file ) && strcmp( opt.crt_file, "none" ) != 0 )
    {
        key_cert_init++;
        if( ( ret = mbedtls_x509_crt_parse_file( &srvcert, opt.crt_file ) ) != 0 )
        {
            ERROR( " failed!  mbedtls_x509_crt_parse_file returned -0x%x", -ret );
            goto exit;
        }
    }
    if( strlen( opt.key_file ) && strcmp( opt.key_file, "none" ) != 0 )
    {
        key_cert_init++;
        if( ( ret = mbedtls_pk_parse_keyfile( &pkey, opt.key_file, "" ) ) != 0 )
        {
            ERROR( " failed!  mbedtls_pk_parse_keyfile returned -0x%x", -ret );
            goto exit;
        }
        INFO("load key file ok.");
    }
    if( key_cert_init == 1 )
    {
        ERROR( " failed!  crt_file without key_file or vice-versa" );
        goto exit;
    }

    if( strlen( opt.crt_file2 ) && strcmp( opt.crt_file2, "none" ) != 0 )
    {
        key_cert_init2++;
        if( ( ret = mbedtls_x509_crt_parse_file( &srvcert2, opt.crt_file2 ) ) != 0 )
        {
            ERROR( " failed!  mbedtls_x509_crt_parse_file(2) returned -0x%x", -ret );
            goto exit;
        }
    }
    if( strlen( opt.key_file2 ) && strcmp( opt.key_file2, "none" ) != 0 )
    {
        key_cert_init2++;
        if( ( ret = mbedtls_pk_parse_keyfile( &pkey2, opt.key_file2, "" ) ) != 0 )
        {
            ERROR( " failed!  mbedtls_pk_parse_keyfile(2) returned -0x%x", -ret );
            goto exit;
        }
    }
    if( key_cert_init2 == 1 )
    {
        ERROR( " failed!  crt_file2 without key_file2 or vice-versa");
        goto exit;
    }
    if( key_cert_init == 0 &&
        strcmp( opt.crt_file, "none" ) != 0 &&
        strcmp( opt.key_file, "none" ) != 0 &&
        key_cert_init2 == 0 &&
        strcmp( opt.crt_file2, "none" ) != 0 &&
        strcmp( opt.key_file2, "none" ) != 0 )
    {
        if( ( ret = mbedtls_x509_crt_parse( &srvcert,
                                    (const unsigned char *) mbedtls_test_srv_crt_rsa,
                                    mbedtls_test_srv_crt_rsa_len ) ) != 0 )
        {
            ERROR( " failed!  mbedtls_x509_crt_parse returned -0x%x", -ret );
            goto exit;
        }
        if( ( ret = mbedtls_pk_parse_key( &pkey,
                                  (const unsigned char *) mbedtls_test_srv_key_rsa,
                                  mbedtls_test_srv_key_rsa_len, NULL, 0 ) ) != 0 )
        {
            ERROR( " failed!  mbedtls_pk_parse_key returned -0x%x", -ret );
            goto exit;
        }
        key_cert_init = 2;

        if( ( ret = mbedtls_x509_crt_parse( &srvcert2,
                                    (const unsigned char *) mbedtls_test_srv_crt_ec,
                                    mbedtls_test_srv_crt_ec_len ) ) != 0 )
        {
            ERROR( " failed!  x509_crt_parse2 returned -0x%x", -ret );
            goto exit;
        }
        if( ( ret = mbedtls_pk_parse_key( &pkey2,
                                  (const unsigned char *) mbedtls_test_srv_key_ec,
                                  mbedtls_test_srv_key_ec_len, NULL, 0 ) ) != 0 )
        {
            ERROR( " failed!  pk_parse_key2 returned -0x%x", -ret );
            goto exit;
        }
        key_cert_init2 = 2;
    }

    /*
     * 3. Setup stuff
     */
    DEBUG( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    opt.transport,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        ERROR( " failed! mbedtls_ssl_config_defaults returned -0x%x", -ret );
        goto exit;
    }

    /* The default algorithms profile disables SHA-1, but our tests still
       rely on it heavily. Hence we allow it here. A real-world server
       should use the default profile unless there is a good reason not to. */
    if( opt.allow_sha1 > 0 )
    {
        crt_profile_for_test.allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 );
        mbedtls_ssl_conf_cert_profile( &conf, &crt_profile_for_test );
        mbedtls_ssl_conf_sig_hashes( &conf, ssl_sig_hashes_for_test );
    }

    if( opt.auth_mode != DFL_AUTH_MODE )
        mbedtls_ssl_conf_authmode( &conf, opt.auth_mode );

    if( opt.cert_req_ca_list != DFL_CERT_REQ_CA_LIST )
        mbedtls_ssl_conf_cert_req_ca_list( &conf, opt.cert_req_ca_list );

    if( ( ret = mbedtls_ssl_conf_max_frag_len( &conf, opt.mfl_code ) ) != 0 )
    {
        ERROR(" failed! mbedtls_ssl_conf_max_frag_len returned %d", ret );
        goto exit;
    };

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( opt.tickets == MBEDTLS_SSL_SESSION_TICKETS_ENABLED )
    {
        if( ( ret = mbedtls_ssl_ticket_setup( &ticket_ctx,
                        mbedtls_ctr_drbg_random, &ctr_drbg,
                        MBEDTLS_CIPHER_AES_256_GCM,
                        opt.ticket_timeout ) ) != 0 )
        {
            ERROR( " failed! mbedtls_ssl_ticket_setup returned %d", ret );
            goto exit;
        }

        mbedtls_ssl_conf_session_tickets_cb( &conf,
                mbedtls_ssl_ticket_write,
                mbedtls_ssl_ticket_parse,
                &ticket_ctx );
    }

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        mbedtls_ssl_conf_ciphersuites( &conf, opt.force_ciphersuite );


    if( opt.version_suites != NULL )
    {
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[0],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_0 );
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[1],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_1 );
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[2],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_2 );
        mbedtls_ssl_conf_ciphersuites_for_version( &conf, version_suites[3],
                                          MBEDTLS_SSL_MAJOR_VERSION_3,
                                          MBEDTLS_SSL_MINOR_VERSION_3 );
    }

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        mbedtls_ssl_conf_legacy_renegotiation( &conf, opt.allow_legacy );

    if( strcmp( opt.ca_path, "none" ) != 0 &&
        strcmp( opt.ca_file, "none" ) != 0 )
    {
        mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    }
    if( key_cert_init )
    {
        mbedtls_pk_context *pk = &pkey;
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, pk ) ) != 0 )
        {
            ERROR( " failed! mbedtls_ssl_conf_own_cert returned %d", ret );
            goto exit;
        }
    }
    if( key_cert_init2 )
    {
        mbedtls_pk_context *pk = &pkey2;
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert2, pk ) ) != 0 )
        {
            ERROR( " failed! mbedtls_ssl_conf_own_cert returned %d", ret );
            goto exit;
        }
    }


    if( opt.min_version != DFL_MIN_VERSION )
        mbedtls_ssl_conf_min_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.min_version );

    if( opt.max_version != DFL_MIN_VERSION )
        mbedtls_ssl_conf_max_version( &conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.max_version );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        ERROR( " failed! mbedtls_ssl_setup returned -0x%x", -ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );

    ret = mbedtls_net_set_nonblock( &client_fd );
    mbedtls_ssl_conf_read_timeout( &conf, opt.read_timeout );
    
    DEBUG( "init ssl ok");
    return 0;
    
reset:
    if( received_sigterm )
    {
        ERROR( " interrupted by SIGTERM (not in net_accept())");
        if( ret == MBEDTLS_ERR_NET_INVALID_CONTEXT )
            ret = 0;

        goto exit;
    }

    if( ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT )
    {
        ERROR( "  ! Client initiated reconnection from same port" );
    }

    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        ERROR("Last error was: %d - %s", ret, error_buf );
    }


    mbedtls_ssl_session_reset( &ssl );


    return 0;    
usage:
    if( ret == 0 )
        ret = 1;

    mbedtls_printf( USAGE );

    list = mbedtls_ssl_list_ciphersuites();
    while( *list )
    {
        ERROR(" %-42s", mbedtls_ssl_get_ciphersuite_name( *list ) );
        list++;
        if( !*list )
            break;
        ERROR(" %s", mbedtls_ssl_get_ciphersuite_name( *list ) );
        list++;
    }
    goto exit;

exit:
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        ERROR("Last error was: -0x%X - %s", -ret, error_buf );
    }

    ERROR( "  . Cleaning up..." );
    mbedtls_net_free( &listen_fd );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_x509_crt_free( &srvcert2 );
    mbedtls_pk_free( &pkey2 );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_ssl_ticket_free( &ticket_ctx );
    return 1;    
}

int MbedTlsParams::do_handshake() {
    int ret;
    INFO( "  . Performing the SSL/TLS handshake..." );

    ret = mbedtls_ssl_handshake( &ssl );

    if( mbedtls_status_is_ssl_in_progress( ret ) )
        return 0;


    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        INFO( " hello verification requested");
        ret = 0;
        return 1;
    }
    else if( ret != 0 )
    {
        ERROR( " failed! mbedtls_ssl_handshake returned -0x%x", -ret );

        if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
        {
            char vrfy_buf[512];
            flags = mbedtls_ssl_get_verify_result( &ssl );

            mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

            INFO( "verify info:%s", vrfy_buf );
        }

        return 1;
    }
    else /* ret == 0 */
    {
        INFO( " ok    [ Protocol is %s ]    [ Ciphersuite is %s ]",
                mbedtls_ssl_get_version( &ssl ), mbedtls_ssl_get_ciphersuite( &ssl ) );
    }

    if( ( ret = mbedtls_ssl_get_record_expansion( &ssl ) ) >= 0 )
        INFO( "    [ Record expansion is %d ]", ret );
    else
        ERROR( "    [ Record expansion is unknown (compression) ]" );

    INFO( "    [ Maximum fragment length is %u ]",
                    (unsigned int) mbedtls_ssl_get_max_frag_len( &ssl ) );

    return 0;
}

int MbedTlsParams::ssl_recv(uint8_t* buf, int& len) {
    len = 0;
    if ( ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER ) {
        return do_handshake();
    }

        int ret = mbedtls_ssl_read( &ssl, buf, 4096);
        if( mbedtls_status_is_ssl_in_progress( ret ) )
        {
            DEBUG( "read zero", ret );
            return 0;
        }
        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    ERROR( " connection was closed gracefully" );
                    break;
                case 0:
                case MBEDTLS_ERR_NET_CONN_RESET:
                    ERROR( " connection was reset by peer" );
                    ret = MBEDTLS_ERR_NET_CONN_RESET;
                    break;
                default:
                    ERROR( " mbedtls_ssl_read returned -0x%x", -ret );
                    break;
            }
            return 1;
        }
        
        if( mbedtls_ssl_get_bytes_avail( &ssl ) == 0 )
        {
            DEBUG( " %d bytes read", ret);
            len = ret;
        }
        else
        {
            int extra_len, ori_len;
            ori_len = ret;
            extra_len = (int) mbedtls_ssl_get_bytes_avail( &ssl );

            /* This read should never fail and get the whole cached data */
            ret = mbedtls_ssl_read( &ssl, buf + ori_len, extra_len );
            if( ret != extra_len || mbedtls_ssl_get_bytes_avail( &ssl ) != 0 )
            {
                ERROR( "  ! mbedtls_ssl_read failed on cached data" );
                return 1;
            }
            DEBUG( " %u bytes read (%u + %u)", ori_len + extra_len, ori_len, extra_len );
            len = ori_len + extra_len;
        }

    return 0;
}
int MbedTlsParams::ssl_write(const std::string& packet) {
    int written,frags;
    uint8_t* buf = (uint8_t*)packet.c_str();
    int len = packet.size();
    int ret;
    for( written = 0, frags = 0; written < len; written += ret, frags++ )
    {
        while( ( ret = mbedtls_ssl_write( &ssl, buf + written, len - written ) )
                       <= 0 )
        {
            if( ret == MBEDTLS_ERR_NET_CONN_RESET )
            {
                ERROR( " failed\n  ! peer closed the connection" );
                return 1;
            }

            if( ! mbedtls_status_is_ssl_in_progress( ret ) )
            {
                ERROR( " failed\n  ! mbedtls_ssl_write returned %d", ret );
                return 1;
            }

        }
    }    
    DEBUG( "%d / %d bytes written in %d fragments", packet.size(), written, frags);
    return 0;
}
int MbedTlsParams::ssl_close()
{
//    mbedtls_net_free( &client_fd );
    return 0;
}
