#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <memory.h>
#include <algorithm>
#include <string>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <assert.h>

#include "sockutl.h"

#ifndef SIOCOUTQ
    #define SIOCOUTQ  TIOCOUTQ
#endif

bool socket_utl::set_nonblock(fd_handle_t socket,bool non_block_or_not)
{
    assert(socket != invalid_handle_t);
    if(socket == invalid_handle_t)
        return false;
    
    int flags = 0;
    do { flags = fcntl(socket, F_GETFL, 0); } while(flags < 0 && errno == EINTR);

    assert(flags >= 0);
    if(flags < 0) //exception protection
        flags = O_RDWR; //set default
    
    int err = 0;
    if(non_block_or_not)
    {
        do { err = fcntl(socket, F_SETFL, flags | O_NONBLOCK); } while( err < 0 && errno == EINTR);
        assert(err != -1);
    }
    else
    {
        int non_block_flags = ~O_NONBLOCK;
        flags &= non_block_flags;
        
        do { err = fcntl(socket, F_SETFL, flags); } while( err < 0 && errno == EINTR);
        assert(err != -1);
    }
    
    return (err != -1);
}
std::string socket_utl::socketaddr_to_string(const uint32_t ipv4_addr)
{
    if(0 == ipv4_addr)
        return std::string("0.0.0.0");
    
    char ipaddr_buf[256] = {0};
    inet_ntop(AF_INET,&ipv4_addr,ipaddr_buf, sizeof(ipaddr_buf));
    return std::string(ipaddr_buf);
}

uint64_t socket_utl::string_to_socketaddr(const std::string ipv4_or_ipv6_addr)
{
    if(ipv4_or_ipv6_addr.empty())
        return 0;
    
    if(is_ipv4_address(ipv4_or_ipv6_addr))
    {
        uint32_t network_addr = 0;
        const int ret = inet_pton(AF_INET,(const char*)ipv4_or_ipv6_addr.c_str(), &network_addr);
        assert(ret == 1);
        return network_addr;
    }
    else
    {
        uint64_t network_addr = 0;
        const int ret = inet_pton(AF_INET6,(const char*)ipv4_or_ipv6_addr.c_str(), &network_addr);
        assert(ret == 1);
        return network_addr;
    }
}
bool        socket_utl::is_ipv4_address(const std::string & ipv4addr)
{
    if( (ipv4addr.size() < 7) || (ipv4addr.size() > 15) )//valid ipv4 len is [7,15]
        return false;
    
    if(ipv4addr.find_first_not_of(".0123456789") != std::string::npos) //if have any chars exclude .0123456789
        return false;

    sockaddr_in addr4;
    //It returns 1 if the address was valid for the specified address family, or 0
    //if the address was not parseable in the specified address family, or -1 if some system error occurred (in which case errno will have been set).  This func-tion is presently valid for AF_INET and AF_INET6.
    const int ret = inet_pton(AF_INET,(const char*)ipv4addr.c_str(), &addr4.sin_addr);
    return (ret == 1);
}
int socket_utl::get_next_private_ip(const std::string& ipv4addr, uint16_t& private_ip_seq, uint32_t& private_ip) {
    uint32_t ip = socket_utl::string_to_socketaddr(ipv4addr);
    private_ip_seq++;
    if (private_ip_seq == 0) {
        private_ip_seq = 1;
    }
    ip = ntohl(ip) + private_ip_seq;
    ip = htonl(ip);
    private_ip = ip;
    return 0;
}
uint64_t      socket_utl::convert_ipv4_address_to_int64(const std::string & ipv4, const int real_port,const int logic_port) //return network_order uint64_t
{
    const uint64_t port_int64 = htons(real_port);
    uint32_t ip_int_32 = 0;
    if(ipv4.size() > 0)
        inet_pton(AF_INET,(const char*)ipv4.c_str(), &ip_int_32);
    
    return  (((uint64_t)(logic_port & 0xFFFF)) << 48 ) | ((port_int64 << 32)| ip_int_32);
}

uint64_t       socket_utl::convert_ipv4_address_to_int64(const sockaddr_in & ipv4_saddr,const int logic_port)       //return network_order uint64_t
{
    uint64_t int_ipv4_addr = (((uint64_t)ipv4_saddr.sin_port) << 32) | ipv4_saddr.sin_addr.s_addr;
    int_ipv4_addr |= (((uint64_t)(logic_port & 0xFFFF)) << 48);
    return int_ipv4_addr;
}
void           socket_utl::convert_ipv4_address_form_int64(const uint64_t & in_composed_value,std::string & out_ipv4, int & out_real_port,int & out_logic_port)
{
    sockaddr_in  ipv4_addr = {0};
    ipv4_addr.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
    ipv4_addr.sin_len = sizeof(sockaddr_in);
#endif
    ipv4_addr.sin_addr.s_addr = (in_composed_value & 0xFFFFFFFF); //lower 32bit
    ipv4_addr.sin_port = ((in_composed_value >> 32) & 0xFFFF);
    
    out_logic_port = (int)(in_composed_value >> 48);
    socket_utl::get_address((struct sockaddr *)&ipv4_addr, out_ipv4, out_real_port);
}

void           socket_utl::convert_ipv4_address_form_int64(const uint64_t & in_composed_value,sockaddr_in & out_ipv4_saddr,int & out_logic_port)
{
    out_ipv4_saddr.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
    out_ipv4_saddr.sin_len = sizeof(sockaddr_in);
#endif
    out_ipv4_saddr.sin_addr.s_addr = (in_composed_value & 0xFFFFFFFF); //lower 32bit
    out_ipv4_saddr.sin_port = ((in_composed_value >> 32) & 0xFFFF);
    
    out_logic_port = (int)(in_composed_value >> 48);
}
bool socket_utl::get_peer_ipv4_address(fd_handle_t s, sockaddr_in & saddr)
{
    if(s != invalid_handle_t)
    {
        memset(&saddr,0,sizeof(saddr));
#ifdef WIN_PLATFORM
        int nLength = sizeof(saddr);
#else
        socklen_t nLength = sizeof(saddr);
#endif
        if(getpeername(s, (sockaddr*)&saddr, &nLength) == 0)
        {
            return true;
        }
    }
    return false;
}
bool socket_utl::get_address(sockaddr * net_addr,std::string & ip, int & port)
{
    if(NULL == net_addr)
        return false;
    
    char namebuf[INET6_ADDRSTRLEN] = {0};
    if(net_addr->sa_family == AF_INET) //ipv4
    {
        sockaddr_in* ipv4_addr =((sockaddr_in*)net_addr);
#ifdef HAVE_SIN_LEN        
        assert(sizeof(sockaddr_in) == ipv4_addr->sin_len);
#endif
        inet_ntop(AF_INET,&ipv4_addr->sin_addr,namebuf, INET_ADDRSTRLEN);
        ip = namebuf;
        port = ntohs(ipv4_addr->sin_port);
        return true;
    }
    else if(net_addr->sa_family == AF_INET6)
    {
        sockaddr_in6 * ipv6_addr = (sockaddr_in6*)net_addr;
#ifdef HAVE_SIN_LEN        
        assert(sizeof(sockaddr_in6) == ipv6_addr->sin6_len);
#endif
        inet_ntop(AF_INET6, &ipv6_addr->sin6_addr, namebuf, INET6_ADDRSTRLEN),
        ip = namebuf;
        port = ntohs(ipv6_addr->sin6_port);
        return true;
    }
    return false;
}
int  socket_utl::socket_sendto(fd_handle_t s, const void* pBuf, const size_t nBufLen,int flags,struct sockaddr* psaddr, int psaddrLen)
{
    ssize_t nReturn = 0;
    for(;;)
    {            
        nReturn = ::sendto(s,pBuf, nBufLen, flags,psaddr,psaddrLen);
        
        // repeat until success
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    
#ifdef WIN_PLATFORM
    if(nReturn == SOCKET_ERROR)
    {
        switch(WSAGetLastError())
        {
            case WSAEINTR :
            case WSAEWOULDBLOCK :
            case WSAEINPROGRESS :
            case WSAENOBUFS :
            case WSAEMSGSIZE :
                return 0;
                
            default :
                assert(0);
                break;
        }
        return -1;
    }
#else
    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EAGAIN) || (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {
            if(nerr != EINTR)
                DEBUG("socket_utl::socket_sendto(%d) block(err id=%d,descript=%s)",s,nerr,strerror(nerr));
            
            errno = EAGAIN;
            return 0;
        }
        else if(nerr == EINVAL) //if has invalid params,usally caused by invalid target address
        {
            DEBUG("socket_utl::socket_sendto(%d) invalid params(err id=%d,descript=%s)",s,nerr,strerror(nerr));
            return 0; //keep orignal error code
        }
        else if(nerr == ENOBUFS) //iOS have flow control for datagram socket,that may dont allow send too much data
        {
            DEBUG("socket_utl::socket_sendto(%d) no buffer for socket(err id=%d,descript=%s)",s,nerr,strerror(nerr));
            return 0;
        }
        else
        {
            INFO("socket_utl::socket_sendto(%d) error(id=%d,descript=%s)",s,nerr,strerror(nerr));
            return -1;
        }
    }
#endif
    return static_cast <int>(nReturn);
}
int socket_utl::socket_recvfrom(fd_handle_t s, void* pBuf, const size_t nBufLen, const int flags,struct sockaddr * from_addr,socklen_t * addrlen)
{
    ssize_t nReturn = 0;

    for(;;)
    {
        nReturn = ::recvfrom(s, pBuf, nBufLen, flags,from_addr,addrlen);
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    
#ifdef WIN_PLATFORM
    if(nReturn == SOCKET_ERROR)
    {
        switch(WSAGetLastError())
        {
            case WSAEINTR :
            case WSAEWOULDBLOCK :
            case WSAEINPROGRESS :
            case WSAENOBUFS :
            case WSAEMSGSIZE :
                return 0;
                
            default :
                assert(0);
                break;
        }
        return -1;
    }
    
#else //all other platform
    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EAGAIN) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {
            errno = EAGAIN;
            return 0;
        }
        else
        {
            INFO("socket_recvfrom(%d) error(id=%d,descript=%s",s,nerr,strerror(nerr));
            return -1;
        }
    }
    else if(0 == nReturn)
    {
        errno = 0;
    }
#endif
    return static_cast <int>(nReturn);
}

int socket_utl::socket_send(fd_handle_t s, const void* pBuf, const size_t nBufLen, const int nFlag)
{
    if( (NULL == pBuf) || (0 == nBufLen) )
        return 0;
    
    ssize_t nReturn = 0;
#ifdef WIN_PLATFORM
    nReturn = send(s, (const char*)pBuf, nBufLen, nFlag);
#elif defined(MAC_PLATFORM)
    for(;;)
    {
        nReturn = send(s, pBuf, nBufLen, nFlag);
        
        // repeat until success
        const int last_error = errno;
        if( (nReturn < 0) && ((last_error == EINTR) || (last_error == EPROTOTYPE)) )
        {
            /*
             * Due to a possible kernel bug at least in OS X 10.10 "Yosemite",
             * EPROTOTYPE can be returned while trying to write to a socket that is
             * shutting down. If we retry the write, we should get the expected EPIPE
             * instead.
             */
            continue;
        }
        break;
    }
#else
    for(;;)
    {
        nReturn = send(s, pBuf, nBufLen, nFlag);
        
        // repeat until success
        if( (nReturn < 0) && (errno == EINTR) )
        {
            continue;
        }
        break;
    }
#endif
    
#ifdef WIN_PLATFORM
    if(nReturn == SOCKET_ERROR)
    {
        switch(WSAGetLastError())
        {
            case WSAEINTR :
            case WSAEWOULDBLOCK :
            case WSAEINPROGRESS :
            case WSAENOBUFS :
            case WSAEMSGSIZE :
                return 0;
           
            default :
                ju_assert(0);
                break;
        }
        return -1;
    }
#else
    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EAGAIN) || (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {
            if(nerr != EINTR)
            {
                const int blocking_bytes = socket_utl::get_outqueue_size(s);
                DEBUG("socket_utl::socket_send(%d) block(err id=%d,descript=%s,blocking_bytes(%d))",s,nerr,strerror(nerr),blocking_bytes);
            }

            errno = EAGAIN;
            return 0;
        }
        else
        {
            INFO("socket_utl::socket_send(%d) error(id=%d,descript=%s",s,nerr,strerror(nerr));
            return -1;
        }
    }
#endif
    return static_cast <int>(nReturn);
}

int socket_utl::socket_recv(fd_handle_t s, void* pBuf, const size_t nBufLen, const int flags)
{
    ssize_t nReturn = 0;
#ifdef WIN_PLATFORM
    nReturn = recv(s, (char*)pBuf, nBufLen, flags);
#else
    for(;;)
    {
        nReturn = recv(s, pBuf, nBufLen, flags);
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
#endif
    
#ifdef WIN_PLATFORM
    if(nReturn == SOCKET_ERROR)
    {
        switch(WSAGetLastError())
        {
            case WSAEINTR :
            case WSAEWOULDBLOCK :
            case WSAEINPROGRESS :
            case WSAENOBUFS :
            case WSAEMSGSIZE :
                return 0;

            default :
                assert(0);
                break;
        }
        return -1;
    }
    
#else //all other platform
    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EAGAIN) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {
            if(nerr != EINTR)
            {
                const int unreaded_bytes = socket_utl::get_readable_size(s);
                if(unreaded_bytes > 0)
                    DEBUG("socket_utl::read_socket(%d) block(err id=%d,descript=%s,unreaded_bytes(%d)",s,nerr,strerror(nerr),unreaded_bytes);
                else if( (nerr != EAGAIN) && (nerr != EWOULDBLOCK) )
                    DEBUG("socket_utl::read_socket(%d) block(err id=%d,descript=%s",s,nerr,strerror(nerr));
            }
            errno = EAGAIN;
            return 0;
        }
        else
        {
            INFO("socket_utl::read_socket(%d) error(id=%d,descript=%s",s,nerr,strerror(nerr));
            return -1;
        }
    }
    else if(0 == nReturn)
    {
        errno = 0;
    }
#endif
    return static_cast <int>(nReturn);
}

int socket_utl::get_outqueue_size(fd_handle_t s)
{
    int unsendsize = 0;
    if(ioctl(s,SIOCOUTQ, &unsendsize) >= 0 )
    {
        return unsendsize;
    }
    return -1;
}
int socket_utl::get_readable_size(fd_handle_t s)
{
    u_long nAvailable = -1;
    socket_ioctl(s, FIONREAD, &nAvailable);
    return (int)nAvailable;
}
int socket_utl::socket_ioctl(fd_handle_t s, long cmd, unsigned long* argp)
{
    int nReturn = 0;
    *argp = 0;
    
#ifdef WIN_PLATFORM
    nReturn = ioctlsocket(s, cmd, argp);
    if(nReturn == SOCKET_ERROR)
    {
        switch(WSAGetLastError())
        {
            case WSAEINTR :
            case WSAEWOULDBLOCK :
            case WSAEINPROGRESS :
            case WSAENOBUFS :
            case WSAEMSGSIZE :
                return 0;
                
            default :
                assert(0);
                break;
        }
        return -1;
    }
#else //note ioctl may lock whole kernal which cause multiple thread/cpu core has worse performance
    for(;;)
    {
        nReturn = ioctl(s, cmd, argp);
        if(nReturn < 0 && errno == EINTR)
            continue;
        
        break;
    }
#endif
    return 0;
}


