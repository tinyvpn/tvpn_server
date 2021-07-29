#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <map>
#include <fstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <mutex>

#include "sysutl.h"
#include "fileutl.h"
#include "sockutl.h"
#include "sockhttp.h"
#include "timeutl.h"
#include "stringutl.h"
#include "cJSON.h"
#include "obfuscation_utl.h"
#include "log.h"
#include "ssl_server.h"

const int BUF_SIZE = 4096*2;
struct Connection {
    char packet_buf[BUF_SIZE*2];
    uint16_t packet_len;
    uint16_t protocol;
    int conn_fd;
    std::string user_name;
    std::string device_id;
    uint16_t auth;
    uint32_t out_traffic;
    uint32_t out_packets;
    time_t start;
    time_t end;
    MbedTlsParams* mbedtls_params;
};
struct ConnectionParams {
    fd_handle_t tcp_fd;
    uint16_t protocol;
    uint16_t id;
    std::string user_name;
    std::string device_id;
    uint16_t auth;
    uint32_t in_traffic;
    uint32_t in_packets;
    time_t start;
    time_t end;
    MbedTlsParams* mbedtls_params;
};
struct UdpConnection {
    int sockid;
    uint16_t protocol;
    uint16_t connected;
    sockaddr_in addr;
    time_t udp_timer;    
    
    std::string user_name;
    uint16_t auth;
    uint32_t in_traffic;
    uint32_t out_traffic;
    time_t start;
    time_t end;
    
};
struct Protocol {
    uint16_t id;
    uint16_t port;
    int sock_fd;
};

std::mutex g_mutex;

std::string tun_root_ipv4_address_string = "126.24.0.0";
std::string default_network_eth_device = "eno16777984";//"eno16777984";
int port_number = 51212;  // need to delete
//in_addr_t test_private_ip = inet_addr("126.24.1.99");  // need to delete
std::string g_web_server;
std::string g_listen_ip;
uint16_t g_private_ip_seq = 0;
uint16_t g_obfu_first_four = 0;  
uint16_t g_obfu = 1;
uint32_t g_iv = 0x87654321;
const uint16_t SELECT_NUMBER=64;

Connection g_connections[SELECT_NUMBER];  // connections info, only tcp, less than SELECT_NUMBER
std::map<uint32_t, ConnectionParams> g_client_sock_map;  // key: client private ip, value: client socket fd, only for tcp
std::map<uint32_t, UdpConnection> g_udp_connections;  // udp connections, key: client private ip, value:...
std::vector<Protocol> g_protocols;  // less than 10
std::string g_delay_traffic;  // release tcp socket, delay sending to billing server
extern uint32_t log_level;
int GetProtocolType(std::string& protocol){
    if (protocol == "xtcp")
        return kXtcpType;
    if (protocol == "http")
        return kHttpType;
    if (protocol == "ssl")
        return kSslType;
    if (protocol == "xudp")
        return kXudpType;
    if (protocol == "dns")
        return kDnsType;
    if (protocol == "icmp")
        return kIcmpType;
    printf("protocol error.\n");
    return -1;
}
int json_parse_config(const std::string& ret) {
    cJSON* pRoot = cJSON_CreateObject();
    pRoot = cJSON_Parse(ret.c_str());
    g_obfu_first_four = cJSON_GetObjectItem(pRoot, "obfu_first_four")->valueint;
    g_obfu = cJSON_GetObjectItem(pRoot, "obfu")->valueint;
    tun_root_ipv4_address_string = cJSON_GetObjectItem(pRoot, "tun_root_ipv4_address_string")->valuestring;
    default_network_eth_device = cJSON_GetObjectItem(pRoot, "default_network_eth_device")->valuestring;
//    test_private_ip = inet_addr(cJSON_GetObjectItem(pRoot, "test_private_ip")->valuestring);
    log_level = cJSON_GetObjectItem(pRoot, "log_level")->valueint;
    std::string protocols = cJSON_GetObjectItem(pRoot, "protocols")->valuestring;
    g_web_server = cJSON_GetObjectItem(pRoot, "web_server")->valuestring;
    g_listen_ip = cJSON_GetObjectItem(pRoot, "listen_ip")->valuestring;
    
    std::vector<std::string> values;
    string_utl::split_string(protocols, '.', values);
    for(int i=0;i<values.size()-1;i+=2) {
        Protocol p;
        p.id = GetProtocolType(values[i]);
        if (p.id < 0)
            return 1;
        p.port = string_utl::StringToUInt32(values[i+1]);
        g_protocols.push_back(p);
    }
    for (int i=0;i<g_protocols.size();i++)
        printf ("%d,%d\n", g_protocols[i].id, g_protocols[i].port);
    printf("tun_root_ipv4_address_string:%s,default_network_eth_device:%s,protocols:%s,log_level:%d,obfu:%d, obfu_first_four:%d, web_server:%s\n",
        tun_root_ipv4_address_string.c_str(), default_network_eth_device.c_str(), protocols.c_str(), log_level, g_obfu, g_obfu_first_four, g_web_server.c_str());
    fflush ( stdout ) ;
    cJSON_Delete(pRoot);
    return 0;
}

bool ifconfig(const char * ifname, const char * va, const char *pa)
{
    char cmd[2048] = {0};
    snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask 255.255.0.0 up",ifname, va);
    INFO("ifconfig:%s\n", cmd);
    if (system(cmd) < 0)
    {
        ERROR("sys_utl::ifconfig,interface(%s) with param(%s) and params(%s) fail at error:%d\n",ifname,va,pa,errno);
        return false;
    }
    return true;
}
int send_to_tun_udp(fd_handle_t fd_tun_device, char* ip_packet_data, int ip_packet_len) {
    sys_utl::tun_dev_write(fd_tun_device, (void*)ip_packet_data, ip_packet_len);
    return 0;
}
int send_to_tun(fd_handle_t fd_tun_device, uint16_t conn_id, char* ip_packet_data, int ip_packet_len) {
    int len;
    std::lock_guard<std::mutex> lck (g_mutex);
    // if no buff, process the packet, if having buff, copy to the buff and process the buff
    if (g_connections[conn_id].packet_len != 0) {
        if (ip_packet_len + g_connections[conn_id].packet_len > sizeof(g_connections[conn_id].packet_buf)) {
            DEBUG("relay size over %d", sizeof(g_connections[conn_id].packet_buf));
            g_connections[conn_id].packet_len = 0;
            return 1;
        }
        memcpy(g_connections[conn_id].packet_buf+ g_connections[conn_id].packet_len, ip_packet_data, ip_packet_len);
        ip_packet_data = g_connections[conn_id].packet_buf;
        ip_packet_len += g_connections[conn_id].packet_len;
        g_connections[conn_id].packet_len = 0;
        DEBUG("relayed packet:%d", ip_packet_len);
    }
    if (g_connections[conn_id].protocol == kHttpType) {
        std::string http_packet;
        int http_head_length,http_body_length;
        while(1) {
            if (ip_packet_len == 0)
                break;
            http_packet.assign(ip_packet_data, ip_packet_len);
            if (sock_http::pop_front_xdpi_head(http_packet, http_head_length, http_body_length) != 0) {  // decode http header fail
                DEBUG("relay to next packet:%d,%d,current buff len:%d", conn_id, ip_packet_len, g_connections[conn_id].packet_len);
                if (g_connections[conn_id].packet_len == 0) {
                    memcpy(g_connections[conn_id].packet_buf + g_connections[conn_id].packet_len, ip_packet_data, ip_packet_len);
                    g_connections[conn_id].packet_len += ip_packet_len;
                }
                break;                
            }
            ip_packet_len -= http_head_length;
            ip_packet_data += http_head_length;
            if (g_obfu_first_four == 1)
                obfuscation_utl::decode((unsigned char*)ip_packet_data, 4, g_iv);
            if (g_obfu == 1) {
                obfuscation_utl::decode((unsigned char*)ip_packet_data+4, http_body_length-4, g_iv);
            }
            
            struct ip *iph = (struct ip *)ip_packet_data;
            len = ntohs(iph->ip_len);
            char ip_src[INET_ADDRSTRLEN + 1];
            char ip_dst[INET_ADDRSTRLEN + 1];
            inet_ntop(AF_INET,&iph->ip_src.s_addr,ip_src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET,&iph->ip_dst.s_addr,ip_dst, INET_ADDRSTRLEN);
            
            DEBUG("send to tun,http, from(%s) to (%s) with size:%d,%d,%d,%d",ip_src,ip_dst,len, http_head_length, http_body_length,ip_packet_len);
            sys_utl::tun_dev_write(fd_tun_device, (void*)ip_packet_data, http_body_length);
            time(&g_connections[conn_id].end);
            g_connections[conn_id].out_packets += 1;
            
            ip_packet_len -= http_body_length;
            ip_packet_data += http_body_length;
        }
        return 0;
    } else if (g_connections[conn_id].protocol == kSslType) {
        while(1) {
            if (ip_packet_len == 0)
                break;
            // todo: recv from socket, send to utun1
            if (ip_packet_len < sizeof(struct ip) ) {
                ERROR("less than ip header:%d.", ip_packet_len);
                memcpy(g_connections[conn_id].packet_buf, ip_packet_data, ip_packet_len);
                g_connections[conn_id].packet_len = ip_packet_len;
                break;
            }
            struct ip *iph = (struct ip *)ip_packet_data;
            len = ntohs(iph->ip_len);
            
            if (ip_packet_len < len) {
                if (len > BUF_SIZE) {
                    ERROR("something error1.%x,%x,data:%s",len, ip_packet_len, string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
                    INFO("buff:%d,%s",g_connections[conn_id].packet_len,string_utl::HexEncode(std::string(g_connections[conn_id].packet_buf,g_connections[conn_id].packet_len)).c_str());
                    g_connections[conn_id].packet_len = 0;
                } else {
                    DEBUG("relay to next packet:%d,%d,current buff len:%d", conn_id, ip_packet_len, g_connections[conn_id].packet_len);
                    if (g_connections[conn_id].packet_len == 0) {
                        memcpy(g_connections[conn_id].packet_buf + g_connections[conn_id].packet_len, ip_packet_data, ip_packet_len);
                        g_connections[conn_id].packet_len += ip_packet_len;
                    }
                }
                break;
            }
            
            if (len > BUF_SIZE) {
                ERROR("something error2.%x,%x,data:%s",len, ip_packet_len, string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
                g_connections[conn_id].packet_len = 0;
                break;
            } else if (len == 0) {
                INFO("len is zero.%x,%x",len, ip_packet_len); //string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
                g_connections[conn_id].packet_len = 0;
                break;
            }
            char ip_src[INET_ADDRSTRLEN + 1];
            char ip_dst[INET_ADDRSTRLEN + 1];
            inet_ntop(AF_INET,&iph->ip_src.s_addr,ip_src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET,&iph->ip_dst.s_addr,ip_dst, INET_ADDRSTRLEN);
            
            DEBUG("send to tun, from(%s) to (%s) with size:%d",ip_src,ip_dst,len);
            sys_utl::tun_dev_write(fd_tun_device, (void*)ip_packet_data, len);
            time(&g_connections[conn_id].end);
            g_connections[conn_id].out_packets += 1;
    
            ip_packet_len -= len;
            ip_packet_data += len;
        }
        return 0;
    }    
    
    while(1) {
        if (ip_packet_len == 0)
            break;
        // todo: recv from socket, send to utun1
        if (ip_packet_len < sizeof(struct ip) ) {
            ERROR("less than ip header:%d.", ip_packet_len);
            memcpy(g_connections[conn_id].packet_buf, ip_packet_data, ip_packet_len);
            g_connections[conn_id].packet_len = ip_packet_len;
            break;
        }
        if (g_obfu_first_four == 1)
            obfuscation_utl::decode((unsigned char*)ip_packet_data, 4, g_iv);
        struct ip *iph = (struct ip *)ip_packet_data;
        len = ntohs(iph->ip_len);
        
        if (ip_packet_len < len) {
            if (len > BUF_SIZE) {
                ERROR("something error1.%x,%x,data:%s",len, ip_packet_len, string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
                INFO("buff:%d,%s",g_connections[conn_id].packet_len,string_utl::HexEncode(std::string(g_connections[conn_id].packet_buf,g_connections[conn_id].packet_len)).c_str());
                g_connections[conn_id].packet_len = 0;
            } else {
                DEBUG("relay to next packet:%d,%d,current buff len:%d", conn_id, ip_packet_len, g_connections[conn_id].packet_len);
                if (g_obfu_first_four == 1)
                    obfuscation_utl::encode((unsigned char*)ip_packet_data, 4, g_iv);  // restore data            
                if (g_connections[conn_id].packet_len == 0) {
                    memcpy(g_connections[conn_id].packet_buf + g_connections[conn_id].packet_len, ip_packet_data, ip_packet_len);
                    g_connections[conn_id].packet_len += ip_packet_len;
                }
            }
            break;
        }
        
        if (len > BUF_SIZE) {
            ERROR("something error2.%x,%x,data:%s",len, ip_packet_len, string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
            g_connections[conn_id].packet_len = 0;
            break;
        } else if (len == 0) {
            INFO("len is zero.%x,%x",len, ip_packet_len); //string_utl::HexEncode(std::string(ip_packet_data,ip_packet_len)).c_str());
            g_connections[conn_id].packet_len = 0;
            break;
        }
        // should be ok
        if (g_obfu == 1) {
            obfuscation_utl::decode((unsigned char*)ip_packet_data+4, len-4, g_iv);
    //        DEBUG("after decode:%s", string_utl::HexEncode(std::string(ip_packet_data, ip_packet_len)).c_str());
        }
        char ip_src[INET_ADDRSTRLEN + 1];
        char ip_dst[INET_ADDRSTRLEN + 1];
        inet_ntop(AF_INET,&iph->ip_src.s_addr,ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET,&iph->ip_dst.s_addr,ip_dst, INET_ADDRSTRLEN);
        
        DEBUG("send to tun, from(%s) to (%s) with size:%d",ip_src,ip_dst,len);
        sys_utl::tun_dev_write(fd_tun_device, (void*)ip_packet_data, len);
        time(&g_connections[conn_id].end);
//        g_connections[conn_id].out_traffic += len;
        g_connections[conn_id].out_packets += 1;

        ip_packet_len -= len;
        ip_packet_data += len;
    }

    return 0;
}
void check_udp_connection() {
    time_t curr_timer;
    double seconds;
    std::map<uint32_t, UdpConnection>::iterator it;
    while(1) {
        curr_timer= time(NULL);
        for(it = g_udp_connections.begin(); it != g_udp_connections.end(); ){
            seconds = difftime(curr_timer, it->second.udp_timer);
            if (seconds > 60)  {
                INFO("udp connection timeout, will be erased:%d, private_ip:%x, sockid:%d, protocol:%d, addr:%x",
                    g_udp_connections.size(), it->first, it->second.sockid, it->second.protocol, *(uint32_t*)&it->second.addr.sin_addr);
                it = g_udp_connections.erase(it);
            } else {
                ++it;
            }
        }
        sleep(10);
    }
    return;
}
int StartListen() {
    int sock_fd;
	struct sockaddr_in server_addr;
	int ret;
    int have_udp_protocol = 0;
    int have_tcp_protocol = 0;
    for (int i=0;i<g_protocols.size();i++){
        if (g_protocols[i].id == kXtcpType || g_protocols[i].id == kHttpType){
        	// 创建socket描述符
        	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        		fprintf(stderr,"Socket error:%s\n\a", strerror(errno));
        		exit(1);
        	}

        	// 填充sockaddr_in结构
        	bzero(&server_addr, sizeof(struct sockaddr_in));
        	server_addr.sin_family = AF_INET;
        	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        	server_addr.sin_port = htons(g_protocols[i].port);

        	// 绑定sock_fd描述符
        	if (bind(sock_fd, (struct sockaddr *)(&server_addr), sizeof(struct sockaddr)) == -1) {
        		fprintf(stderr,"Bind error:%s\n\a", strerror(errno));
        		exit(1);
        	}
            INFO("bind ok.");

        	// 监听sock_fd描述符
        	if(listen(sock_fd, 5) == -1) {
        		fprintf(stderr,"Listen error:%s\n\a", strerror(errno));
        		exit(1);
        	}
            INFO("listen:%d ok.", g_protocols[i].port);
            g_protocols[i].sock_fd = sock_fd;
            have_tcp_protocol = 1;
        }
        else if (g_protocols[i].id == kSslType){
            if (ssl_listen( g_protocols[i].port, sock_fd) != 0) {
        		fprintf(stderr,"Listen ssl error:%s\n", strerror(errno));
        		exit(1);
            }
            g_protocols[i].sock_fd = sock_fd;
            INFO("listen ssl:%d ok.", g_protocols[i].port);
            have_tcp_protocol = 1;
        }
        else if (g_protocols[i].id == kXudpType|| g_protocols[i].id == kDnsType){
             sock_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
             if(sock_fd < 0)
             {
                 printf("create socket fail!\n");
                 return -1;
             }
         
             memset(&server_addr, 0, sizeof(server_addr));
             server_addr.sin_family = AF_INET;
//             server_addr.sin_addr.s_addr = htonl(INADDR_ANY); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
             server_addr.sin_addr.s_addr = inet_addr(g_listen_ip.c_str()); 
             server_addr.sin_port = htons(g_protocols[i].port);  //端口号，需要网络序转换
         
             ret = bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
             if(ret < 0)
             {
                 printf("socket bind fail!\n");
                 return -1;
             }
             INFO("bind udp ok:%d", g_protocols[i].port);
             g_protocols[i].sock_fd = sock_fd;
             have_udp_protocol = 1;
        }
    }
    if (have_udp_protocol != 0) {
        std::thread timeout_thread(check_udp_connection);
        timeout_thread.detach();
    }
    if (have_tcp_protocol != 0) {
//        std::thread tcp_timeout_thread(check_tcp_connection);
//        tcp_timeout_thread.detach();
    }
    return 0;
}
int send_to_socket(VpnPacket& vpn_packet) {
    struct ip *iph = (struct ip *)vpn_packet.data();
    
    char ip_src[INET_ADDRSTRLEN + 1];
    char ip_dst[INET_ADDRSTRLEN + 1];
    memset(ip_src,0, sizeof(ip_src));
    memset(ip_dst,0, sizeof(ip_src));
    inet_ntop(AF_INET,&iph->ip_src.s_addr,ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&iph->ip_dst.s_addr,ip_dst, INET_ADDRSTRLEN);
    DEBUG("recv from tun, from(%s) to (%s)%x with size:%d",ip_src,ip_dst,iph->ip_dst.s_addr, vpn_packet.size());
    // todo: send to socket
    std::lock_guard<std::mutex> lck (g_mutex);
    std::map<uint32_t, ConnectionParams>::iterator it = g_client_sock_map.find(iph->ip_dst.s_addr);  // find in tcp map
    if (it == g_client_sock_map.end()) {
        // DEBUG("not find client sockid,dst:%s", ip_dst);
    } else {
        if (it->second.protocol == kSslType) {
            it->second.mbedtls_params->ssl_write(std::string((char*)vpn_packet.data(), vpn_packet.size()));
            it->second.in_traffic += vpn_packet.size();
            it->second.in_packets++;
            time(&it->second.end);
            return 0;
        }

        if (g_obfu_first_four == 1)
            obfuscation_utl::encode((unsigned char*)vpn_packet.data(), 4, g_iv);
        if (g_obfu == 1)  // not encode ip len
            obfuscation_utl::encode((unsigned char*)vpn_packet.data()+4, vpn_packet.size()-4, g_iv);

        if (it->second.protocol == kHttpType) {
            sock_http::push_front_xdpi_head_1(vpn_packet);
            file_utl::write(it->second.tcp_fd, vpn_packet.data(), vpn_packet.size());
            it->second.in_traffic += vpn_packet.size();
            it->second.in_packets++;
            time(&it->second.end);
            return 0;
        }
                
        file_utl::write(it->second.tcp_fd, vpn_packet.data(), vpn_packet.size());
        time(&it->second.end);
        it->second.in_traffic += vpn_packet.size();
        it->second.in_packets++;
//                    socket_utl::socket_send(it->second, buff, readed_from_tun);
        return 0;
    }

    std::map<uint32_t, UdpConnection>::iterator it2 = g_udp_connections.find(iph->ip_dst.s_addr);  // find in udp map
    if (it2 == g_udp_connections.end()) {
        INFO("not find tcp or udp connection:%x", iph->ip_dst.s_addr);
    } else {
        uint16_t len = (uint16_t)vpn_packet.size();
        if (len < 200) {
            char rand_str[80];
            for (int i=0;i<20;i++)
                *(uint32_t*)(rand_str + i*4) = rand();
            vpn_packet.push_back((uint8_t*)rand_str, 80);
        }
        if (g_obfu == 1)  // not encode ip len
            obfuscation_utl::encode((unsigned char*)vpn_packet.data(), vpn_packet.size(), g_iv);
        vpn_packet.push_front((uint8_t*)&len, sizeof(len));
        
        socket_utl::socket_sendto(it2->second.sockid, vpn_packet.data(), vpn_packet.size(), 0, (sockaddr*)&it2->second.addr, sizeof(sockaddr_in));
        time(&it2->second.end);
        it2->second.in_traffic += vpn_packet.size();
    }
    return 0;
}
// command: 1byte premium, 1byte device_id length, device_id, [1byte user_name length, user_name, 1byte user_password length, user_password]
int check_auth(int id, std::string& user_info) {
/*    std::vector<std::string> values;
    string_utl::split_string(user_info, '\n', values);
    if (values.size() != 2) {
        ERROR("parse user auth info fail.");
        return 1;
    }*/
    char* ptr = (char*)user_info.c_str();
    int len = user_info.size();
    uint8_t premium = *(uint8_t*)ptr;
    ptr += 1;
    len -= 1;

    uint8_t data_len;
    data_len = *(uint8_t*)ptr;
    if (len < data_len + 1) {
        ERROR("length error1:%d, len", *(uint8_t*)ptr, len);
        return 1;
    }
    ptr += 1;
    len -= 1;
    std::string device_id(ptr, data_len);
    ptr += data_len;
    len -= data_len;

    std::string user_name, user_password;
    if (premium >=2 ){
        data_len = *(uint8_t*)ptr;
        if (len < data_len + 1) {
            ERROR("length error2:%d, len", *(uint8_t*)ptr, len);
            return 1;
        }
        ptr += 1;
        len -= 1;
        user_name.assign(ptr, data_len);
        ptr += data_len;
        len -= data_len;

        data_len = *(uint8_t*)ptr;
        if (len < data_len + 1) {
            ERROR("length error3:%d, len", *(uint8_t*)ptr, len);
            return 1;
        }
        ptr += 1;
        len -= 1;
        user_password.assign(ptr, data_len);
        ptr += data_len;
        len -= data_len;
    }
    
    uint32_t test_private_ip;
    socket_utl::get_next_private_ip(tun_root_ipv4_address_string, g_private_ip_seq, test_private_ip);

    std::lock_guard<std::mutex> lck (g_mutex);
    INFO("auth ok. id:%d,conn_fd:%d,private_ip:%x,user:%s,device_id:%s", id,  g_connections[id].conn_fd, test_private_ip,user_name.c_str(), device_id.c_str()); //s_addr
    
    ConnectionParams params;
    params.tcp_fd = g_connections[id].conn_fd;
    params.protocol = g_connections[id].protocol;
    params.id = id;
    params.user_name = user_name;
    params.device_id= device_id;
    params.in_traffic = 0;
    params.in_packets = 0;
    params.auth = 1;
    time(&params.start);
    time(&params.end);
    params.mbedtls_params = g_connections[id].mbedtls_params;
    g_client_sock_map[test_private_ip] = params;

    g_connections[id].user_name = user_name;
    g_connections[id].device_id = device_id;
    g_connections[id].auth = 1;

    for (std::map<uint32_t, ConnectionParams>::iterator it=g_client_sock_map.begin(); it!=g_client_sock_map.end(); ++it)                
        INFO("key:%x,value:%d, id:%d, user:%s, device_id:%s", it->first, it->second.tcp_fd, it->second.id, it->second.user_name.c_str(), it->second.device_id.c_str());
    if (g_connections[id].protocol == kSslType) {
        g_connections[id].mbedtls_params->ssl_write(std::string((char*)&test_private_ip, sizeof(test_private_ip)));
    } else if (g_connections[id].protocol == kHttpType){
       // file_utl::write( g_connections[id].conn_fd, (char*)&test_private_ip, sizeof(test_private_ip)); // send private ip
       VpnPacket vpn_packet(4096);
       vpn_packet.push_back((uint8_t*)&test_private_ip, sizeof(test_private_ip));
       if (g_obfu_first_four == 1)
           obfuscation_utl::encode((unsigned char*)vpn_packet.data(), 4, g_iv);
       if (g_obfu == 1)  // not encode ip len
           obfuscation_utl::encode((unsigned char*)vpn_packet.data()+4, vpn_packet.size()-4, g_iv);
       sock_http::push_front_xdpi_head_1(vpn_packet);
       file_utl::write( g_connections[id].conn_fd, vpn_packet.data(), vpn_packet.size()); // send private ip

    }
    return 0;
}
int gen_send_stat_data(std::string& strStat) {
    strStat += (char)8;  // 8 for traffic data

    std::lock_guard<std::mutex> lck (g_mutex);
    for (std::map<uint32_t, ConnectionParams>::iterator it=g_client_sock_map.begin(); it!=g_client_sock_map.end(); ++it) {
        if (it->second.in_traffic + g_connections[it->second.id].out_traffic < 32*1024) {
            continue;
        }
        time_t start_time = std::min(g_connections[it->second.id].start, it->second.start);
        time_t end_time = std::max(g_connections[it->second.id].end, it->second.end);
        
        strStat += it->second.device_id;
        strStat += "\t";
        if (it->second.user_name.empty())
            strStat += "~";
        else
            strStat += it->second.user_name;
        strStat += "\t";
        strStat += time_utl::gmt_date(start_time);
        strStat += "\t";
        strStat += time_utl::gmt_date_time(start_time);
        strStat += "\t";
        strStat += std::to_string(end_time - start_time);
        strStat += "\t";
        strStat += "0";
        strStat += "\t";
        strStat += std::to_string(it->second.in_traffic);
        strStat += "\t";
        strStat += std::to_string(g_connections[it->second.id].out_traffic);
        strStat += "\t";
        strStat += std::to_string(it->second.in_packets);
        strStat += "\t";
        strStat += std::to_string(g_connections[it->second.id].out_packets);
        strStat += "\n";
        g_connections[it->second.id].out_traffic = 0;
        g_connections[it->second.id].out_packets= 0;
        time(&g_connections[it->second.id].start);
        time(&g_connections[it->second.id].end);
        time(&it->second.start);
        time(&it->second.end);
        it->second.in_traffic = 0;
        it->second.in_packets = 0;
    }
    strStat += g_delay_traffic;
    g_delay_traffic.clear();
    return 0;
}
int clear_client_socket(const int index, const int fd) {
    std::lock_guard<std::mutex> lck (g_mutex);
    for (std::map<uint32_t, ConnectionParams>::iterator it=g_client_sock_map.begin(); it!=g_client_sock_map.end(); ++it) {
        if (it->second.tcp_fd == fd) {
            if (it->second.in_traffic + g_connections[it->second.id].out_traffic != 0) {
                time_t start_time = std::min(g_connections[it->second.id].start, it->second.start);
                time_t end_time = std::max(g_connections[it->second.id].end, it->second.end);
                std::string strStat;
                strStat += it->second.device_id;
                strStat += "\t";
                if (it->second.user_name.empty())
                    strStat += "~";
                else
                    strStat += it->second.user_name;
                strStat += "\t";
                strStat += time_utl::gmt_date(start_time);
                strStat += "\t";
                strStat += time_utl::gmt_date_time(start_time);
                strStat += "\t";
                strStat += std::to_string(end_time - start_time);
                strStat += "\t";
                strStat += "0";
                strStat += "\t";
                strStat += std::to_string(it->second.in_traffic);
                strStat += "\t";
                strStat += std::to_string(g_connections[it->second.id].out_traffic);
                strStat += "\t";
                strStat += std::to_string(it->second.in_packets);
                strStat += "\t";
                strStat += std::to_string(g_connections[it->second.id].out_packets);
                strStat += "\n";
                g_connections[it->second.id].out_traffic = 0;
                g_connections[it->second.id].out_packets= 0;
                time(&g_connections[it->second.id].start);
                time(&g_connections[it->second.id].end);
                g_delay_traffic += strStat;
            }
            INFO("g_client_sock_map erase ok, remain:%d, id:%d, fd:%d, private_ip:%x, saved_id:%d",
                g_client_sock_map.size()-1, index, fd, it->first, it->second.id);
//            if (it->second.protocol == kSslType)
//                delete it->second.mbedtls_params;
            g_client_sock_map.erase(it);
            break;
        }
    }
    if (g_connections[index].protocol == kSslType)
        delete g_connections[index].mbedtls_params;
    
    g_connections[index].packet_len = 0;
    g_connections[index].protocol = 999;
    g_connections[index].auth = 0;
    g_connections[index].user_name.clear();
    g_connections[index].device_id.clear();
    g_connections[index].conn_fd = 0;
    g_connections[index].out_traffic = 0;
    return 0;
}
void check_tcp_connection(int* fd_A) {
    time_t curr_timer;
    double seconds;
    //std::lock_guard<std::mutex> lck (g_mutex);
    int fd_count = 0;
    int clean_fd_count = 0;
    for (int i = 0; i < SELECT_NUMBER; i++) {
        if (fd_A[i] == 0)
            continue;
        fd_count++;
        time(&curr_timer);
        seconds = difftime(curr_timer, g_connections[i].end);
        INFO("check_tcp_connection, time:%d,%d,difftime:%f", curr_timer, g_connections[i].end, seconds);
        if (seconds > 120)  {  // no data traffic
            clean_fd_count++;
            clear_client_socket(i, fd_A[i]);
            fd_A[i] = 0;
        }
    }
    INFO("check_tcp_connection. remain:%d, fd count:%d, clean fd:%d", g_client_sock_map.size(), fd_count, clean_fd_count);

    return;
}

void stat_thread() {
    while(1) {
        std::string strStat;
        gen_send_stat_data(strStat);
        if (strStat.size() <= 1){
            sleep(60);
            continue;
        }
        
        int sock =socket(PF_INET, SOCK_STREAM, 0);
        if(sock == -1) {
            ERROR("socket() error");
            return;
        }
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family=AF_INET;
        serv_addr.sin_addr.s_addr=inet_addr(g_web_server.c_str());
        serv_addr.sin_port=htons(60315);
        
        if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))==-1) {
            ERROR("connect data server error!");
            sleep(60);
            continue;
        }
        int ret=file_utl::write(sock, (char*)strStat.c_str(), strStat.size());
        if (ret <= 0) {
            ERROR("send statistic data to server error.");
        } else {
            INFO("send statistic data ok: %s", strStat.c_str()+1);
        }
        //ret=file_utl::read(sock, ip_packet_data, BUF_SIZE);
        
        close(sock);
        sleep(60);
    }
}
int main(int argc, const char * argv[]) {
	char buff[BUF_SIZE];
    srand(time(0));

    for (int i=0;i<SELECT_NUMBER;i++) {
        g_connections[i].conn_fd = 0;
        g_connections[i].packet_len = 0;
        g_connections[i].protocol = 999;
    }
/*    int len;
    uint32_t iv;
    len = 4; //100 + rand()%2000;
    iv = rand();
    for (int i=0;i<len;i++)
        buff[i]=rand()%256;
    std::string strtemp(buff, len);
    printf("str:%s\n", string_utl::HexEncode(strtemp).c_str());
    obfuscation_utl::encode((unsigned char*)buff, len, iv);
    strtemp.assign(buff,len);
    printf("after obfuscation, str:%s\n", string_utl::HexEncode(strtemp).c_str());
    obfuscation_utl::decode((unsigned char*)buff, len, iv);
    strtemp.assign(buff,len);
    printf("str:%s\n", string_utl::HexEncode(strtemp).c_str());  
    return 1;*/
    std::string strStat;
    time_t t1;
    time(&t1);
    strStat += time_utl::gmt_date_time(t1) + ",";
    strStat += time_utl::gmt_date_time();
    printf("test time:%s\n", strStat.c_str());

    OpenFile("./vlog.txt");
    std::ifstream is("config.json");
    is.read(buff, sizeof(buff));
    if (is.gcount() == 0) {
        ERROR("read config error");
        return 1;
    }
    INFO("config,%d:%s", is.gcount(), buff);
    is.close();

    if (json_parse_config(buff) != 0) {
        ERROR("json parse error.");
        return 0;
    }
    
    std::string dev_name;
    std::vector<fd_handle_t> queue_handles;
    const int queues_count = sys_utl::open_tun_mq_devivce(dev_name,1,queue_handles);
    if (queues_count<=0){
        ERROR("queues_count errror");
        return 1;
    }
    const fd_handle_t fd_tun_device = queue_handles.front();//give the first fd to read & write queue
    queue_handles.erase(queue_handles.begin());

    INFO("open tun succ, fd:%d",fd_tun_device);

    socket_utl::set_nonblock(fd_tun_device, true);
    if (ifconfig(dev_name.c_str(),tun_root_ipv4_address_string.c_str(),tun_root_ipv4_address_string.c_str()) == false)
        return 1;

    INFO("ifconfig ok.");
    
    std::string routing_cmd = std::string("route add -net ") + tun_root_ipv4_address_string + " dev " + dev_name;
    INFO("init,add routing:%s, for device(%s)",routing_cmd.c_str(),dev_name.c_str());
    if (system(routing_cmd.c_str()) < 0) {
        return 1;
    }

    if(default_network_eth_device.size() > 0) //already configure the default output eth device
    {
        //sample: sudo iptables -t nat -A POSTROUTING -s 11.11.0.0/16 -o eth1 -j MASQUERADE
        const std::string delete_rule_cmd = std::string("iptables -t nat -D POSTROUTING -s ") + tun_root_ipv4_address_string + "/16 -o " + default_network_eth_device + " -j MASQUERADE";
        system(delete_rule_cmd.c_str()); //clean first to avoid duplicated rule
        
        const std::string add_proxy_cmd = std::string("iptables -t nat -A POSTROUTING -s ") + tun_root_ipv4_address_string + "/16 -o " + default_network_eth_device + " -j MASQUERADE";                
        system(add_proxy_cmd.c_str());
        INFO("open_tun_device,add itable rule(%s) to:%s for device(%s)",add_proxy_cmd.c_str(),default_network_eth_device.c_str(),dev_name.c_str());
    }
    
    const std::string delete_iptable_forward_rule = std::string("iptables -D FORWARD -s ")  + tun_root_ipv4_address_string + "/16 -j ACCEPT";
    system(delete_iptable_forward_rule.c_str());
    const std::string add_iptable_forward_rule = std::string("iptables -I FORWARD -s ")  + tun_root_ipv4_address_string + "/16 -j ACCEPT";
    system(add_iptable_forward_rule.c_str());
    
    g_client_sock_map.clear();

    if (StartListen() != 0) {
        printf("listen fail.\n");
        return 0;
    }
    std::thread _stat_thread(stat_thread);    
    _stat_thread.detach();
    
    fd_set fdsr;
    fd_set listen_fds;
    int ret;
    int conn_fd;
    int fd_A[SELECT_NUMBER];  // exactly same as the g_connections[i].conn_fd
    int maxfd = 0;
    memset(fd_A, 0, SELECT_NUMBER*sizeof(int));

    FD_ZERO(&listen_fds);
    // 将socket描述符添加到文件描述符集
    for (int i=0;i<g_protocols.size();i++){    
        FD_SET(g_protocols[i].sock_fd, &listen_fds);
        maxfd = std::max(maxfd, g_protocols[i].sock_fd);
    }
    maxfd = std::max(maxfd, fd_tun_device);
    FD_SET(fd_tun_device, &listen_fds);
    int listen_maxfd = maxfd;
    VpnPacket vpn_packet(4096);
    time_t curr_timer;
    time_t last_timer;
    double seconds;
    while(1) {
        fdsr= listen_fds;
        maxfd = listen_maxfd;

        // 将活动的连接添加到文件描述符集
        for (int i = 0; i < SELECT_NUMBER; i++) {
            if (fd_A[i] != 0) {
                FD_SET(fd_A[i], &fdsr);
                maxfd = std::max(maxfd, fd_A[i]);
            }
        }

        int nReady = select(maxfd + 1, &fdsr, NULL, NULL, NULL);
        if (nReady < 0) {
            ERROR("select error:%d", nReady);
            break;
        } else if (nReady == 0) {
            ERROR("select timeout");
            continue;
        }
        // check tcp connections
        curr_timer= time(NULL);
        seconds = difftime(curr_timer, last_timer);
        if (seconds > 60)  {
            check_tcp_connection(fd_A);
            last_timer = curr_timer;
        }
        
        // tcp new connections or udp data
        for (int i=0;i<g_protocols.size();i++){    
            if (!FD_ISSET(g_protocols[i].sock_fd, &fdsr)) 
                continue;
            if (g_protocols[i].id == kXtcpType || g_protocols[i].id == kHttpType || g_protocols[i].id == kSslType){
                struct sockaddr_in client_addr;
                socklen_t len = sizeof(client_addr);
                conn_fd = accept(g_protocols[i].sock_fd, (struct sockaddr*)&client_addr,&len);
                if (conn_fd <= 0) {
                    printf("accept error\n");
                    continue;
                }

                // add new connection to fd_A[]
                for(int j = 0; j < SELECT_NUMBER; j++){
                    if(fd_A[j]!=0)
                        continue;
                    fd_A[j] = conn_fd;
                    maxfd = std::max(maxfd, conn_fd);

                    std::lock_guard<std::mutex> lck (g_mutex);
                    g_connections[j].protocol = g_protocols[i].id;
                    g_connections[j].conn_fd= conn_fd;
                    g_connections[j].out_traffic = 0;
                    g_connections[j].out_packets = 0;
                    time(&g_connections[j].start);
                    time(&g_connections[j].end);
                    if (g_protocols[i].id == kSslType) {
                        MbedTlsParams* params =  new MbedTlsParams(conn_fd);
                        g_connections[j].mbedtls_params = params;
                    }
                    
                    INFO("new connection client[%d],protocol:%d, peer_ip:%s:%d,conn_fd:%d", j, g_protocols[i].id,
                           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), conn_fd); //s_addr
                    
                    break;
                }
                if (--nReady == 0)  // read over
                    break;
            }
            else if (g_protocols[i].id == kXudpType) {
                sockaddr_in from_addr = {0};
                socklen_t addrlen = sizeof(from_addr);
                int readed_size = socket_utl::socket_recvfrom(g_protocols[i].sock_fd,buff, sizeof(buff), 0, (sockaddr*)&from_addr,&addrlen);
                if (readed_size < sizeof(struct ip)) {
                    ERROR("recv udp size error:%d", readed_size);
                    if (--nReady == 0)  // read over
                        break;
                    else continue;                    
                }
                char* buff2;
                if ( *(uint16_t*)buff > readed_size - 2) {
                    ERROR("udp data length error,%d,%d", *(uint16_t*)buff, readed_size);
                    continue;
                }
                buff2 = buff + sizeof(uint16_t);
                if (g_obfu == 1) {
                    obfuscation_utl::decode((unsigned char*)buff2, readed_size - 2, g_iv);
                }
                readed_size = *(uint16_t*)buff;
                struct ip *iph = (struct ip *)buff2;
                
                char ip_src[INET_ADDRSTRLEN + 1];
                char ip_dst[INET_ADDRSTRLEN + 1];
                memset(ip_src,0, sizeof(ip_src));
                memset(ip_dst,0, sizeof(ip_src));
                inet_ntop(AF_INET,&iph->ip_src.s_addr,ip_src, INET_ADDRSTRLEN);
                inet_ntop(AF_INET,&iph->ip_dst.s_addr,ip_dst, INET_ADDRSTRLEN);

                std::map<uint32_t, UdpConnection>::iterator it = g_udp_connections.find(iph->ip_src.s_addr);
                if (it == g_udp_connections.end()) {
                    if (readed_size == 0 && strncmp(buff2, "request", 7)==0) {  // new udp connection
                        UdpConnection u;
                        u.protocol = g_protocols[i].id;
                        u.connected = 1;
                        u.addr = from_addr;
                        u.sockid = g_protocols[i].sock_fd;
                        
                        uint32_t test_private_ip;
                        socket_utl::get_next_private_ip(tun_root_ipv4_address_string, g_private_ip_seq, test_private_ip);
                        INFO("new udp connection client[%d] peer:%x.%x,private_ip:%x", i, from_addr.sin_addr.s_addr,from_addr.sin_port, test_private_ip); //s_addr
                        std::string data((char*)&test_private_ip, sizeof(test_private_ip));
                        int rand_len = rand()%300 + 400;
                        for (int k=0;k < rand_len/4;k++) {
                            uint32_t r = rand();
                            data += std::string((char*)&r, sizeof(r));
                        }
                        socket_utl::socket_sendto(g_protocols[i].sock_fd, data.c_str(), data.size(), 0, (sockaddr*)&from_addr, sizeof(from_addr));
                        g_udp_connections[test_private_ip] = u;
                    } else {
                        DEBUG("not find session:%x,data:%s",iph->ip_src.s_addr, string_utl::HexEncode(std::string(buff, 9)).c_str());
                    }  // drop other packets
                } else {  // send to tun
                    DEBUG("recv from udp, from %s to %s, size:%d", ip_src, ip_dst, readed_size);
                    it->second.udp_timer = time(NULL);
                    // todo: send to tun1
                    send_to_tun_udp(fd_tun_device, buff2, readed_size);
                }
                if (--nReady == 0)  // read over
                    break;
            }
            else if (g_protocols[i].id == kDnsType) {
            }
        }
        if (nReady == 0)
            continue;
        if (FD_ISSET(fd_tun_device, &fdsr)) {  // recv from tun
            int readed_from_tun;
            vpn_packet.reset();            
            readed_from_tun = sys_utl::tun_dev_read(fd_tun_device, vpn_packet.data(), vpn_packet.remain_size());
            vpn_packet.set_back_offset(vpn_packet.front_offset()+readed_from_tun);
            
            if(readed_from_tun > sizeof(struct ip)) {
                send_to_socket(vpn_packet);
            }else {
                INFO("read tun error.");
            }
            if (--nReady == 0)  // read over
                continue;
        }
        // check every client sockets
        for (int i = 0; i < SELECT_NUMBER; i++) {
            if (!FD_ISSET(fd_A[i], &fdsr)) {
                continue;
            }

            if (g_connections[i].protocol == kSslType) {  // error
                int len;
                if (g_connections[i].mbedtls_params->ssl_recv((uint8_t*)buff, len) != 0) { 
                    ERROR("ssl recv error.");
                    g_connections[i].mbedtls_params->ssl_close();
                    FD_CLR(fd_A[i], &fdsr);
                    clear_client_socket(i, fd_A[i]);
                    fd_A[i] = 0;

                    if (--nReady == 0)  // read over
                        break;            
                    else continue;
                }
                if (len == 0) {  // handshake not over
                    if (--nReady == 0)  // read over
                        break;            
                    else continue;
                }
                if (g_connections[i].auth == 0) {
                    std::string str_request(buff, len);
                    check_auth(i, str_request);
                } else { // todo: send to tun1
                    send_to_tun(fd_tun_device, i, buff, len);
                    std::lock_guard<std::mutex> lck (g_mutex);
                    g_connections[i].out_traffic += len;
                }
            } else {            // http
                int status = 0;
                ret = file_utl::read(fd_A[i], buff, BUF_SIZE);
                if (ret <= 0) {  // close socket
                    close(fd_A[i]);
                    FD_CLR(fd_A[i], &fdsr);
                    clear_client_socket(i, fd_A[i]);
                    fd_A[i] = 0;
                } else {
                    DEBUG("recv from socket, size:%d", ret);
                    
                    if (g_connections[i].auth == 0) {
                        std::string user_info(buff, ret);
                        int http_head_length,http_body_length;
                        if (sock_http::pop_front_xdpi_head(user_info, http_head_length, http_body_length) != 0) {  // decode http header fail
                    //        DEBUG("relay to next packet:%d,%d,current buff len:%d", conn_id, ip_packet_len, g_connections[conn_id].packet_len);
                            ERROR("not known client connection.");
                            status = 1;
                        } else {
                            int ip_packet_len = ret;          
                            char* ip_packet_data = buff;
                            ip_packet_len -= http_head_length;
                            ip_packet_data += http_head_length;
                            obfuscation_utl::decode((unsigned char*)ip_packet_data, http_body_length, g_iv);
                            std::string recv_data(ip_packet_data, ip_packet_len);
                            DEBUG("recv auth:%s",  string_utl::HexEncode(recv_data).c_str());
                            check_auth(i, recv_data);
                        }
                    } else // todo: send to tun1
                        send_to_tun(fd_tun_device, i, buff, ret);
                    
                    if (status == 0) {
                        std::lock_guard<std::mutex> lck (g_mutex);
                        g_connections[i].out_traffic += ret;
                    }
                }
            }
            
            if (--nReady == 0)  // read over
                break;            
        }
    }

    for (int i = 0; i < SELECT_NUMBER; i++) {
        if (fd_A[i] != 0) {
            close(fd_A[i]);
        }
    }
    printf("server quit.\n");
    fflush ( stdout );
    return 0;
}
