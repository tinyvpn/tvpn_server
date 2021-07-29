#include "sockhttp.h"
#include <assert.h>
#include <errno.h>

#include "timeutl.h"
#include "stringutl.h"
#include "vpn_packet.h"

//for better peroramcne we encode '/' as well at end of name
const char * global_http_server_names[] = {
   "Apache/",
   "httpd/",
   "Nginx/",
   "Apache/",
   "Jetty/",
   "Nginx/",
   "NodeJ/",
   "Apache/",
   "IIS/",
   "GWS/"
};
std::string http_version_info;
std::string http_useragent_line;
std::string http_host_name;
uint32_t out_packets = 0;

void  sock_http::init_http_head() {
    //as default it is HTTP 1.1
    const int http_major_version = 1;
    const int http_feature_version = 1;
    const int http_minor_version   = 0;
    
    http_version_info = std::string("HTTP/") + string_utl::Int32ToString(http_major_version) + "." + 
        string_utl::Int32ToString(http_feature_version);

    const std::string  const_line_break = "\r\n";
    std::vector<std::string> http_head_useragent_candidate;
    //iPhone iOS 11.1 Safari

    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1"));
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1"));

    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (iPhone; CPU iPhone OS 11_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B93 Safari/604.1"));
    //iPhone iOS 10.3.3 Safari
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1"));
    //iPod safari
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (iPod; CPU iPhone OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A300 Safari/602.1"));
    //iPad Safari
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (iPad; CPU OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A300 Safari/602.1"));

    //Mac Safari
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.1 Safari/603.1.30"));
    //Mac Chrome
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"));
    //Windows IE 11
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Windows NT 6.3; Win64, x64; Trident/7.0; rv:11.0) like Gecko"));
    //Windows Chrome
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"));

    //Android https://developers.whatismybrowser.com/useragents/explore/operating_system_name/android/
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Linux; Android 6.0.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.83 Mobile Safari/537.36"));
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Linux; Android 6.0.1; SM-G935S Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Mobile Safari/537.36"));
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36"));
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36"));
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36"));
    http_head_useragent_candidate.push_back(std::string("Mozilla/5.0 (Linux; Android 6.0; HTC One X10 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36"));

    //return [0,http_head_useragent_line.size()-1];

    const int random_user_agent_pick = time_utl::get_random((int)http_head_useragent_candidate.size());
    http_useragent_line = std::string("User-Agent: ") + http_head_useragent_candidate[random_user_agent_pick] + const_line_break;

    http_host_name = string_utl::get_random_domain_name();

}
std::string   sock_http::get_http_method(const int http_bin_pdu_size_int)
{
    std::string selected_http_method_string;
    #ifndef LINUX_PLATFORM
    int m_connect_to_port = 1;
    #else
    int m_connect_to_port = 0;
    #endif
    if(0 != m_connect_to_port) //client
    {
        selected_http_method_string = "GET";
        if(out_packets++ > 1) // ensure let first 1 packet use GET which simulate to download main page
        {
            if(http_bin_pdu_size_int > 1024) //big packet use POST first
                selected_http_method_string = "POST";
            else if((http_bin_pdu_size_int % 3) == 1) //random using POST or GET
                selected_http_method_string = "POST";
            else if((http_bin_pdu_size_int % 3) == 2) //random using POST or GET
                selected_http_method_string = "PUT";
        }
    }
    else //server
    {
        selected_http_method_string = std::string("HTTP");
    }
    return selected_http_method_string;
}
std::string   sock_http::get_http_host_name()
{
    if(http_host_name.empty() == false)
        return http_host_name;
    
    return string_utl::get_random_domain_name();
}

//write xdpi head at front of buffer and return how many bytes writed
int32_t  sock_http::push_front_xdpi_head_1(VpnPacket& out_packet)
{
    //default go to http0
    
    //get raw pdu size
    const int          http_bin_pdu_size_int = out_packet.size();
    const std::string  http_method = get_http_method(http_bin_pdu_size_int);
    const std::string  http_hostname = get_http_host_name();
    
    int   http_head_writed_size = 0;
    if(http_method == std::string("HTTP") ) //not-client
        http_head_writed_size = write_http_response_head_1(http_bin_pdu_size_int, out_packet);
    else
        http_head_writed_size = write_http_request_head_1(http_method,http_hostname,http_bin_pdu_size_int,out_packet);
    
    //return how many bytes of http head writed into out_http_packet
    if(http_head_writed_size <= 0) //write http head fail
    {
        //exception,close socket
        ERROR("Juhttppacket_t::push_front_xdpi_head_1,failed for http_method(%s) and http_hostname(%s) with http_bin_pdu_size_int=%d",http_method.c_str(),http_hostname.c_str(),http_bin_pdu_size_int);
        return -1;
    }
    return http_head_writed_size;
}
//return how many bytes of http head writed into out_http_packet
int32_t  sock_http::write_http_response_head_1(const int http_bin_pdu_size_int,VpnPacket& out_http_packet)
{
    //here out_http_packet must be empty already
    int                 final_http_head_size_int = 0;
    std::string         final_http_head_method_line;
    const std::string   const_http_line_break = "\r\n";
    
    //for performance
    final_http_head_method_line.reserve(512);//512 bytes is enough
    
    const uint32_t random_seed = time_utl::get_randomu();
    //now know how encode bin pdu size by alpha
    {
        std::string http_head_method_line    = std::string("HTTP/1.1 200 OK\r\n");
        //append date
        {
            const std::string date_time = std::string("Date: ") + time_utl::gmt_http_date_time() + const_http_line_break;
            http_head_method_line += date_time;
        }
        //add extra other lines here if need pass DPI
        {
            //build server line
            const int random_server_name_offset = time_utl::get_random(sizeof(global_http_server_names) / sizeof(const char*));
            const std::string http_head_server_name = global_http_server_names[random_server_name_offset];
            
            const uint32_t random_version = time_utl::get_randomu();
            const std::string server_version_string = string_utl::Int32ToString((random_version >> 16) & 0x07) + "." + string_utl::Int32ToString(random_version & 0x07);
            
            http_head_method_line += (std::string("Server: ") + http_head_server_name + server_version_string + const_http_line_break);
        }
        
        std::string http_head_other_lines;
        {
            http_head_other_lines += (std::string("Cache-Control: max-age=") + string_utl::Int32ToString(time_utl::get_randomu() >> 16) + "\r\n");
            http_head_other_lines += std::string("Connection: keep-alive\r\n"); //append other lines here
            http_head_other_lines += (std::string("Expires: ") + time_utl::gmt_http_date_time(random_seed >> 24) + "\r\n");
        }
        
        //const int random_mime_type_offset = time_utl::get_random(sizeof(global_http_mime_types) / sizeof(const char*));
        const std::string mime_type = string_utl::get_random_http_mime_type();
        std::string http_head_content_type_line   = std::string("Content-Type: ") + mime_type +  const_http_line_break;
        
        //std::string http_head_content_type_line   = std::string("Content-Type: image/jpeg") + const_http_line_break;
        std::string http_head_content_encode_line;
        if(http_bin_pdu_size_int % 2 == 0)
            http_head_content_encode_line = std::string("Content-Encoding: deflate, gzip") + const_http_line_break;
        else
            http_head_content_encode_line = std::string("Content-Encoding: gzip") + const_http_line_break;

        std::string http_head_content_length_line = std::string("Content-Length: ") + string_utl::UInt32ToString(http_bin_pdu_size_int) + const_http_line_break;
        //"\r\n" (const_http_line_break) added as HTTP SPEC requirement
        final_http_head_size_int = (int)(http_head_method_line.size() + http_head_content_type_line.size() + http_head_content_encode_line.size() + http_head_other_lines.size() + http_head_content_length_line.size() + const_http_line_break.size());
        
        //generate final method line string
        final_http_head_method_line = http_head_method_line;
        //#2 push other lines
        final_http_head_method_line += http_head_other_lines;
        //#3 push content type line
        final_http_head_method_line += http_head_content_type_line;
        //#4 push content encode line
        final_http_head_method_line += http_head_content_encode_line;
        //#5 push content length line
        final_http_head_method_line += http_head_content_length_line;
        //#6 HTTP spec ask append "\r\n" at end of http header
        final_http_head_method_line += const_http_line_break;
        if( final_http_head_method_line.size() != final_http_head_size_int)
        {
            ERROR("Juhttppacket_t::write_http_response_head_1,critical bug as bad encode for final_http_head(%s) != final_http_head_size_int(%d)",final_http_head_method_line.c_str(),final_http_head_size_int);
            errno = EINVAL;
            return -1;
        }
        
        //start to push http heads into memory
        out_http_packet.push_front((uint8_t*)final_http_head_method_line.data(), (int32_t)final_http_head_method_line.size());
    }
    
//    DEBUG("Juhttppacket_t::write_http_response_head_1,http head %d bytes and bin content %d bytes,final_http_head=%s",final_http_head_size_int,http_bin_pdu_size_int,final_http_head_method_line.c_str());
    return final_http_head_size_int;
}

//return how many bytes of http head writed into out_http_packet
int32_t  sock_http::write_http_request_head_1(const std::string & http_method,const std::string & peer_host_name,const int http_bin_pdu_size_int,VpnPacket& out_http_packet)
{
    //here out_http_packet must be empty already
    int                 final_http_head_size_int = 0;
    std::string         final_http_head_method_line;
    const std::string   const_http_line_break = "\r\n";
    
    //for performance
    final_http_head_method_line.reserve(512);//512 bytes is enough
    
    //now know how encode bin pdu size by alpha
    const std::string http_bin_pdu_size_string = string_utl::number_to_alpha(http_bin_pdu_size_int);
    std::string http_host_line;
    {
        const size_t domain_anycast_pos = peer_host_name.find_first_of('*');
        if(domain_anycast_pos != std::string::npos) //peer is wild certifcation,convert to www.
        {
            //*.google.com -> www.google.com
            http_host_line = "Host: www" + peer_host_name.substr(domain_anycast_pos + 1) + const_http_line_break;
        }
        else
        {
            //Host: www.google.com
            http_host_line = std::string("Host: ") + peer_host_name + const_http_line_break;
        }
        
        const std::string selected_http_method_string = http_method;    //default method
        
        //"GET / HTTP 1.1\r\n"
        //const std::string   random_html_file = string_utl::number_to_alpha(time_utl::get_random()) + ".html";
        std::string   random_html_file;
        const std::string   http_head_method_line = selected_http_method_string + " /" + random_html_file  + " " + http_version_info + const_http_line_break;
        //http_host_line like         "Host: www.google.com\r\n"
        //m_http_useragent_line like  "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B93 Safari/604.1\r\n"
        
        const int enum_max_head_settings = 5;
        std::string  http_head_settings[enum_max_head_settings];
        http_head_settings[0] = std::string("Connection: keep-alive\r\n"); //append other lines here
        http_head_settings[1] = std::string("Accept-Language: en-US,en\r\n"); //append other lines here
            http_head_settings[2] = std::string("Content-Type: ") + string_utl::get_random_http_mime_type() + "\r\n";
        //const std::string http_accept_types = std::string("Accept: text/html;image/*,*/*\r\nAccept-Encoding: gzip, deflate\r\n");
        http_head_settings[3] = std::string("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n");
        http_head_settings[4] = std::string("Cache-Control: max-age=") + string_utl::Int32ToString(time_utl::get_randomu() >> 16) + "\r\n";
        //add extra other lines here if need pass DPI
        
        std::string http_head_other_lines;
        {
            const int random_offset = (int)time_utl::get_random(enum_max_head_settings);
            for(int i = random_offset; i < enum_max_head_settings; ++i)
            {
                http_head_other_lines += http_head_settings[i];
            }
            for(int i = 0; i < random_offset; ++i)
            {
                http_head_other_lines += http_head_settings[i];
            }
        }
        
        //"Content-Length: xxx\r\n"
        std::string http_head_content_length_line = "Content-Length: " + string_utl::UInt32ToString(http_bin_pdu_size_int) + const_http_line_break;
        //"\r\n" (const_http_line_break) added as HTTP SPEC requirement
        
        //now we know how length of total packet and http head as HTTP Spec
        //since we need append bin size(alpha string) into first line, so must add http_bin_pdu_size_string.size()
        final_http_head_size_int = (int)(http_head_method_line.size() + http_host_line.size() + http_useragent_line.size() + http_head_other_lines.size() + http_head_content_length_line.size() + const_http_line_break.size());
        
        //generate final method line string
        final_http_head_method_line = http_head_method_line;
        //start to push http heads into memory
        //#2 push host line
        final_http_head_method_line += http_host_line;
        //#3 push other lines
        final_http_head_method_line += http_head_other_lines;
        //#4 push useragent line
        final_http_head_method_line += http_useragent_line;
        //#5 push content length line
        final_http_head_method_line += http_head_content_length_line;
        //#6 HTTP spec ask append "\r\n" at end of http header
        final_http_head_method_line += const_http_line_break;
        
        if(final_http_head_method_line.size() != final_http_head_size_int)
        {
            ERROR("Juhttppacket_t::write_http_request_head_1,critical bug as bad encode for final_http_head(%s) != final_http_head_size_int(%d)",final_http_head_method_line.c_str(),final_http_head_size_int);
            errno = EINVAL;
            return -1;
        }
        
        //write whole http head
        out_http_packet.push_front((uint8_t*)final_http_head_method_line.data(), (int32_t)final_http_head_method_line.size());
    }
    
    DEBUG("Juhttppacket_t::write_http_request_head_1,http head %d bytes and bin content %d bytes,final_http_head=%s",final_http_head_size_int,http_bin_pdu_size_int,final_http_head_method_line.c_str());
    return final_http_head_size_int;
}

int sock_http::pop_front_xdpi_head(std::string& http_header, int& http_head_length, int& http_body_length)
{
    int m_http_peer_code_version = 1;  // not important
    std::vector<std::string> header_lines;
    if(parse_http_head(http_header,header_lines))
    {
        int http_body_abolute_pos = 0;
        bool  is_standard_html_packet = false;
        for(int i = 0; i < header_lines.size(); ++i)
        {
            std::string & http_line = header_lines[i];
            http_body_abolute_pos += http_line.size();
            if(http_line.size() < 8) //at least 8 chars
            {
                if( (http_line.size() == 2) && (http_line[0] == '\r') && (http_line[1] == '\n') )//found end of http header
                {
                    http_head_length = http_body_abolute_pos;
                    if(m_http_peer_code_version < 1) //at least version 1
                        m_http_peer_code_version = 1;
                    
                    break; //stop parse http header
                }
                else //skip those small line ,it should not happen
                {
                    continue;
                }
            }
            
            if((http_line[0] == 'S') && (http_line[1] == 'e') && (http_line[2] == 'r') && (http_line[3] == 'v') && (http_line.find("Server: ") == 0)) //response head
            {
                //HTTP/1.1 200 OK\r\n
                //Server: Apache/zzzzz\r\n    
                const std::string http_length_string = read_boundry_string(http_line, std::string("/"), std::string("\r"));
                if(parse_http_length_by_alphacode(http_length_string,http_head_length,http_body_length))
                {
                    m_http_peer_code_version = 0; //must be old version
                    break; //stop parse remain header since we got length already
                }
            }
            else if( (0 == i) && (http_line[0] == 'G') && (http_line[1] == 'E') && (http_line[2] == 'T') && (http_line.find(".html") != std::string::npos) )
            {
                //"GET /zzxxx.html HTTP/1.1\r\n"
                const std::string http_length_string = read_boundry_string(http_line, std::string("/"), std::string("."));
                if(parse_http_length_by_alphacode(http_length_string,http_head_length,http_body_length))
                {
                    m_http_peer_code_version = 0; //must be old version
                    break; //stop parse remain header since we got length already
                }
            }
            else if( (0 == i) && (http_line[0] == 'P') && (http_line[1] == 'O') && (http_line[2] == 'S') && (http_line[3] == 'T') && (http_line.find(".html") != std::string::npos) )
            {
                //"POST /zzxxx.html HTTP/1.1\r\n"
                const std::string http_length_string = read_boundry_string(http_line, std::string("/"), std::string("."));
                if(parse_http_length_by_alphacode(http_length_string,http_head_length,http_body_length))
                {
                    m_http_peer_code_version = 0; //must be old version
                    break; //stop parse remain header since we got length already
                }
            }
            else if( (http_line[0] == 'C') && (http_line[1] == 'o') && (http_line[2] == 'n') && (http_line[3] == 't') && (http_line.find("Content-Length: ") == 0) )//Content-Length:
            {
                //"Content-Length: xxx\r\n;
                const std::string http_content_length_string = read_boundry_string(http_line, std::string(" "), std::string("\r"));
                if(string_utl::digital_string(http_content_length_string) == false)//content length must be digital
                {
                    ERROR("Juhttppacket_t::pop_front_xdpi_head_1,invalid http head without bound char for first line = %s,size:%d",http_line.c_str(),(int)http_content_length_string.size());
                    errno = EINVAL;
                    return -1; //invalid packet
                }
                else
                {
                    http_body_length = string_utl::StringToInt32(http_content_length_string);
                }
            }
            else if( (http_line[0] == 'C') && (http_line[1] == 'o') && (http_line[2] == 'n') && (http_line[3] == 't') && (http_line.find("Content-Type: ") == 0) )//Content-Type:
            {
                const std::string http_type_string = read_boundry_string(http_line, std::string("/"), std::string("\r"));
                if(http_type_string == "css") //Content-Type: text/css\r\n
                {
                    is_standard_html_packet = true;
                }
                else if(http_type_string == "html") //Content-Type: text/html\r\n
                {
                    is_standard_html_packet = true;
                }
                else if(http_type_string == "xml") //Content-Type: text/xml\r\n
                {
                    is_standard_html_packet = true;
                }
            }
        }
        if( (0 == http_head_length) || (http_header.size() < (http_head_length + http_body_length)) ) //whole packet not ready yet
        {
            errno = EAGAIN; //Reset error to again to avoid close
            return 1;
        }
        
        if( 0 == http_head_length ) //whole packet not ready yet
        {
            errno = EAGAIN; //Reset error to again to avoid close
            ERROR("http parse error.");
            return 1;
        }
        
//        http_packet.pop_front(http_head_length); //pop http headers,the remain is the raw data
        if(0 == http_body_length) //allow http standard http header only
        {
            errno = EAGAIN; //Reset error to again to avoid close
        }
        else if(is_standard_html_packet)//just skip the standard html packet
        {
//            http_packet.pop_front(http_body_length); //pop http body
            http_body_length = 0;
            errno = EAGAIN; //Reset error to again to avoid close
        }
        DEBUG("http_head_length:%d,http_body_length:%d", http_head_length, http_body_length);
        return 0;
    }
    else
    {
        errno = EAGAIN; //Reset error to again to avoid close
        return 1;
    }
    return 1;
}
//return string without start_boundry_letters and end_boundry_letters
std::string   sock_http::read_boundry_string(const std::string & line_string,const std::string start_boundry_letters,const std::string end_boundry_letters)
{
    if(line_string.empty())
        return std::string();
    
    std::size_t _begin_pos = std::string::npos;
    std::size_t _end_pos = std::string::npos;
    for(int i = 0; i < start_boundry_letters.size(); ++i)
    {
        _begin_pos = line_string.find_first_of(start_boundry_letters[i]);
        if(_begin_pos != std::string::npos)//found start letter
            break;
    }
    
    for(int i = 0; i < end_boundry_letters.size(); ++i)
    {
        _end_pos = line_string.find_first_of(end_boundry_letters[i]);
        if(_end_pos != std::string::npos)//found end letter
            break;
    }
    
    if( (_begin_pos != std::string::npos) && (_end_pos != std::string::npos) && (((int)_end_pos - (int)_begin_pos - 1) > 0) ) //at least 1 letter
    {
        const std::string  boundtry_string = line_string.substr(_begin_pos+1,_end_pos - _begin_pos - 1);
        return boundtry_string;
    }
    return std::string();
}

bool   sock_http::parse_http_length_by_alphacode(const std::string & http_length_info_alpha,int & http_head_size,int & http_body_size)
{
    if(http_length_info_alpha.size() >= 3) //at least 3 letter
    {
        if( http_length_info_alpha.find_first_of(" .*-+/0123456789\r\n") == std::string::npos)//all are alpha letters
        {
            const std::string http_head_size_alpha = http_length_info_alpha.substr(0,2);//always two char
            const std::string http_body_size_alpha = http_length_info_alpha.substr(2); //all other chars for whole packet
            
            if(http_body_size_alpha.size() <= 4)//biggest packet is 25-25-25-25 = 25*26*26*26 + 25*26*26 + 25*26 + 25 = 439400 + 16900 + 675 = 456975,round 446KB
            {
                int decode_http_head_size = 0;
                int decode_http_body_size = 0;
                decode_http_head_size = string_utl::alpha_to_number(http_head_size_alpha);
                decode_http_body_size = string_utl::alpha_to_number(http_body_size_alpha);
                if( (decode_http_head_size < 1024) && (decode_http_body_size < 1500) )
                {
                    http_head_size = decode_http_head_size;
                    http_body_size = decode_http_body_size;
                    return true;
                }
            }
        }
    }
    return false;
}
bool  sock_http::parse_http_head(const std::string & input,std::vector<std::string> & lines)
{
    if(input.empty())
        return false;
    
    std::string::size_type begin_pos = 0;
    std::string::size_type pos_of_split = input.find("\r\n",begin_pos);
    while(pos_of_split != std::string::npos)
    {
        lines.push_back(input.substr(begin_pos,pos_of_split + 2 - begin_pos)); //include \r\n
        if(begin_pos == pos_of_split) //the last end \r\n
            break;
        
        begin_pos = pos_of_split + 2; //skip boundary
        pos_of_split = input.find_first_of("\r\n",begin_pos);
    }
    return (lines.size() > 0);
}

