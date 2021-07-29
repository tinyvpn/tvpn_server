#ifndef __SOCKUTL_H__
#define __SOCKUTL_H__
#include "base.h"
#if defined(WIN_PLATFORM)
    #include "windows.h"
#else
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif

class socket_utl
{
public: //TCP/UDP/IP/ICMP checksum
    static bool set_nonblock(fd_handle_t socket,bool non_block_or_not);
    static bool is_ipv4_address(const std::string & ipv4addr);
    static std::string    socketaddr_to_string(const uint32_t ipv4);    //convert network order IPv4  to readable string
    static uint64_t       string_to_socketaddr(const std::string ipv4_or_ipv6); //return uint32_t value(network_order) for ipv4_addr
    static int get_next_private_ip(const std::string& ipv4addr, uint16_t& private_ip_seq, uint32_t& private_ip);
    //[16bit logic port][16bit: ipv4 port][32bit:ipv4 addr]
    static uint64_t       convert_ipv4_address_to_int64(const std::string & ipv4, const int real_port,const int logic_port = 0);//return network_order uint64_t
    static uint64_t       convert_ipv4_address_to_int64(const sockaddr_in & ipv4_saddr,const int logic_port = 0);      //return network_order uint64_t
    static void           convert_ipv4_address_form_int64(const uint64_t & in_composed_value,std::string & out_ipv4, int & out_real_port,int & out_logic_port);
    static void           convert_ipv4_address_form_int64(const uint64_t & in_composed_value,sockaddr_in & out_ipv4_saddr,int & out_logic_port);
    static bool           get_peer_ipv4_address(fd_handle_t in_s, sockaddr_in & out_saddr);//make sure it is ipv4 socket before call it    
    static bool           get_address(sockaddr * in_net_addr,std::string & out_ip, int & out_out_port);    
    //return value: > 1 = how many bytes sendout,-1 means error(see errno),0 means dont have byte send out.  just for UDP/ICMP/IP socket
    static int          socket_sendto(fd_handle_t s,const void* pBuf, const size_t nBufLen,const int flags,struct sockaddr* psaddr, int psaddrLen);
    static int          socket_recvfrom(fd_handle_t s, void* pBuf, const size_t nBufLen, const int flags,struct sockaddr * from_addr,socklen_t * addrlen);
    //return value: > 1 = how many bytes sendout,-1 means error(see errno),0 means dont have byte send out
        //only avaiable for TCP or connected UDP socket
    static int          socket_send(fd_handle_t s, const void* pBuf, const size_t nBufLen, const int nFlag = 0);
    //return value: > 1 = how many bytes readout,-1 means error(see errno),0 means dont have byte read out
    static int          socket_recv(fd_handle_t s, void* pBuf, const size_t nBufLen, const int flags = 0);
    static int  get_outqueue_size(fd_handle_t s); //how many bytes are at sending buffer/outband queue of socket
    static int  get_readable_size(fd_handle_t s); //how many bytes can be read at current socket buffer    
    static int  socket_ioctl(fd_handle_t s, long cmd, unsigned long* argp);    
};

#endif
