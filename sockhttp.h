#ifndef __SOCKHTTP_H__
#define __SOCKHTTP_H__

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>

#include "base.h"
#include "vpn_packet.h"
class sock_http
{
public:
    static std::string   get_http_method(const int http_bin_pdu_size_int);
    static std::string get_http_host_name();
    static void  init_http_head();
    static int32_t push_front_xdpi_head_1(VpnPacket& out_packet);
    static int32_t write_http_response_head_1(const int http_bin_pdu_size_int, VpnPacket& out_http_packet);
    static int32_t write_http_request_head_1(const std::string & http_method,const std::string & peer_host_name,const int http_bin_pdu_size_int, VpnPacket& out_http_packet);
    static std::string read_boundry_string(const std::string & line_string,const std::string start_boundry_letters,const std::string end_boundry_letters);
    static bool parse_http_length_by_alphacode(const std::string & http_length_info_alpha,int & http_head_size,int & http_body_size);
    static bool parse_http_head(const std::string & input,std::vector<std::string> & lines);
    static int pop_front_xdpi_head(std::string& http_header, int& http_head_length, int& http_body_length);
};
#endif
