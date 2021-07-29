#ifndef __BASE_H__
#define __BASE_H__
#include "log.h"

#define invalid_handle_t -1
typedef int32_t             fd_handle_t;    //have to be int32_t to compatible with file description that -1 means invalid

/* Note: May be cast to struct iovec. refe socket'sendmsg/ writev(2). */
typedef struct ju_buf {
    void*    mem_ptr;
    size_t   length;  //
}ju_buf_t;

#if defined(LINUX_PLATFORM) || defined(ANDROID_PLATFORM)
    #undef HAVE_SIN6_LEN
    #undef HAVE_SIN_LEN
    #undef HAVE_SA_LEN
    #undef HAVE_SCONN_LEN
#else
#ifndef HAVE_SIN6_LEN  //linux,ios,android all have sockaddr_in6.sin6_len
    #define  HAVE_SIN6_LEN
#endif

#ifndef HAVE_SIN_LEN  //linux,ios,android all have sockaddr_in.sin_len
    #define  HAVE_SIN_LEN
#endif

#ifndef HAVE_SA_LEN  //linux,ios,android all have sockaddr.sa_len
    #define HAVE_SA_LEN
#endif
#endif

enum ProtocolType {
    kXtcpType=0,
    kHttpType,
    kSslType,
    kXudpType=8,
    kDnsType,
    kIcmpType=16,
};

#endif
