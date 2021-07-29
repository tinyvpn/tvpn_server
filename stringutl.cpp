#include "stringutl.h"
#include "timeutl.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <algorithm>

const char kHexAlphabet[] = "0123456789abcdef";
const char kHexLookup[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7,  8,  9,  0,  0,  0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };


std::string string_utl::HexEncode(const std::string& str) {
    uint32_t size(str.size());
    std::string hex_output(size * 2, 0);
    for (size_t i(0), j(0); i != size; ++i) {
        hex_output[j++] = kHexAlphabet[static_cast<unsigned char>(str[i]) / 16];
        hex_output[j++] = kHexAlphabet[static_cast<unsigned char>(str[i]) % 16];
    }
    return hex_output;
}

std::string string_utl::HexDecode(const std::string& str) {
    uint32_t size(str.size());
    if (size % 2) return "";

    std::string non_hex_output(size / 2, 0);
    for (size_t i(0), j(0); i != size / 2; ++i) {
        non_hex_output[i] = (kHexLookup[static_cast<int>(str[j++])] << 4);
        non_hex_output[i] |= kHexLookup[static_cast<int>(str[j++])];
    }
    return non_hex_output;
}

//max UIN64_T is 18 44 67 44 07 37 09 55 16 15 = total 20 chars,can not over 21(since +/- chars need at some case)
int32_t   string_utl::StringToInt32(const std::string & string_value)
{
    if(string_value.empty() || string_value.size() > 21) //can not over 21(since +/- chars need at some case)
        return 0;
    
    return atoi(string_value.c_str());
}
uint32_t   string_utl::StringToUInt32(const std::string & string_value)
{
    if(string_value.empty() || string_value.size() > 21) //can not over 21
        return 0;
    
    return (uint32_t)atoi(string_value.c_str());
}

int64_t   string_utl::StringToInt64(const std::string & string_value)
{
    if(string_value.empty() || string_value.size() > 21) //can not over 21
        return 0;
    
    return atoll(string_value.c_str());
}
uint64_t   string_utl::StringToUInt64(const std::string & string_value)
{
    if(string_value.empty() || string_value.size() > 21) //can not over 21
        return 0;
    
    return (uint64_t)atoll(string_value.c_str());
}
std::string   string_utl::Int32ToString(const int32_t int32value)
{
    char szBuff[32] = {0};
    const int inBufLen = sizeof(szBuff);
    snprintf(szBuff,inBufLen,"%d",int32value);
    
    return std::string(szBuff);
}
std::string   string_utl::UInt32ToString(const uint32_t uint32value)
{
    char szBuff[32] = {0};
    const int inBufLen = sizeof(szBuff);
    snprintf(szBuff,inBufLen,"%u",uint32value);
    
    return std::string(szBuff);
}

std::string   string_utl::Int64ToString(const int64_t int64value)
{
    char szBuff[32] = {0};
    const int inBufLen = sizeof(szBuff);
    snprintf(szBuff,inBufLen,"%lld",int64value);
    
    return std::string(szBuff);
}
std::string   string_utl::UInt64ToString(const uint64_t uint64value)
{
    char szBuff[32] = {0};
    const int inBufLen = sizeof(szBuff);
    snprintf(szBuff,inBufLen,"%llu",uint64value);
    
    return std::string(szBuff);
}

bool  string_utl::split_string(const std::string & input,const char split_char,std::vector<std::string> & values)
{
    if(input.empty())
        return false;
    
    std::string::size_type begin_pos = 0;
    std::string::size_type pos_of_split = input.find_first_of(split_char,begin_pos);
    if (pos_of_split == std::string::npos) {
        values.push_back(input);
        return (values.size() > 0);
    }
    while(pos_of_split != std::string::npos)
    {
        if(pos_of_split != begin_pos)
            values.push_back(input.substr(begin_pos,pos_of_split - begin_pos)); //[)
        begin_pos = pos_of_split + 1; //skip boundary
        pos_of_split = input.find_first_of(split_char,begin_pos);
        if(pos_of_split == std::string::npos) //not find the last split-char
        {
            if(begin_pos < input.size())
            {
                values.push_back(input.substr(begin_pos)); //put the remaining section
            }
        }
    }
    return (values.size() > 0);
}

bool  string_utl::split_string(const std::string & input,const std::string & boundry_letters,std::vector<std::string> & values)
{
    if(input.empty())
        return false;
    
    std::string::size_type begin_pos = 0;
    std::string::size_type pos_of_split = input.find_first_of(boundry_letters,begin_pos);
    while(pos_of_split != std::string::npos)
    {
        if(pos_of_split != begin_pos)
            values.push_back(input.substr(begin_pos,pos_of_split - begin_pos)); //[)
        begin_pos = pos_of_split + 1; //skip boundary
        pos_of_split = input.find_first_of(boundry_letters,begin_pos);
        if(pos_of_split == std::string::npos) //not find the last split-char
        {
            if(begin_pos < input.size())
            {
                values.push_back(input.substr(begin_pos)); //put the remaining section
            }
        }
    }
    return (values.size() > 0);
}

bool  string_utl::split_string2(const std::string & input,const char split_char,std::vector<std::string> & values)
{
    if(input.empty())
        return false;
    
    std::string::size_type begin_pos = 0;
    std::string::size_type pos_of_split = input.find_first_of(split_char,begin_pos);
    while(pos_of_split != std::string::npos)
    {
        if(pos_of_split != begin_pos)
            values.push_back(input.substr(begin_pos,pos_of_split - begin_pos + 1)); //[]
        begin_pos = pos_of_split + 1; //skip boundary
        pos_of_split = input.find_first_of(split_char,begin_pos);
        if(pos_of_split == std::string::npos) //not find the last split-char
        {
            if(begin_pos < input.size())
            {
                values.push_back(input.substr(begin_pos)); //put the remaining section
            }
        }
    }
    return (values.size() > 0);
}
//alpha code: map ['a','b',... 'x','y','z']  to [0,1,...25]
std::string   string_utl::number_to_alpha(const int32_t number) //encode number to alpha52
{
    std::string alpha_number;
    if(0 == number)
    {
        alpha_number.push_back('a');
        return alpha_number;
    }
    
    uint32_t absolute_number = 0;
    if(number < 0)
        absolute_number = -number;
    else
        absolute_number = number;
    
    const uint32_t base = 26;//a,b,c,...,x,y,z
    while (absolute_number != 0)
    {
        const int alpha_index = absolute_number % base;
        alpha_number.push_back(alpha_index + 'a');
        absolute_number = absolute_number / base;
    }
    if(number < 0)
        alpha_number.push_back('-'); //put negative sign at end because we do reverse right after
    
    std::reverse(alpha_number.begin(), alpha_number.end());
    return alpha_number;
}

const char* _utl_global_http_university_domains_dictionary[] = {
    "www.biola.edu",
    "www.colostate.edu",
    "www.ua.edu",
    "www.famu.edu",
    "www.unh.edu",
    "www.lsu.edu",
    "www.kennesaw.edu",
    "www.gvltec.edu",
    "www.umass.edu",
    "www.bu.edu",
    "www.northeastern.edu",
    "www.fsu.edu",
    "www.sc.edu",
    "www.berkeley.edu",
    "www.ucf.edu",
    "www.alasu.edu",
    "www.fit.edu",
    "www.gsu.edu",
    "www.uis.edu",
    "www.rit.edu",
    "www.uky.edu",
    "www.regis.edu",
    "www.nyit.edu",
    "www.emory.edu",
    "www.ucla.edu",
    "www.indiana.edu",
    "www.regent.edu",
    "www.missouristate.edu",
    "www.usm.edu",
    "www.memphis.edu",
    "www.lamar.edu",
    "www.brown.edu",
    "www.ecu.edu",
    "www.harvard.edu",
    "www.gatech.edu",
    "www.clemson.edu",
    "www.asu.edu",
    "www.cornell.edu",
    "www.yale.edu",
    "www.caltech.edu",
    "www.uga.edu",
    "www.txstate.edu",
    "www.admissions.umd.edu",
    "www.nd.edu",
    "www.uchicago.edu",
    "www.umich.edu",
    "www.princeton.edu",
    "www.stanford.edu",
    "www.yale.edu",
};

//exclude google and facebook,instagram,snapchat,telegram who are prevent at most vpn-use country
const char* _utl_global_http_edu_domains_dictionary[] = {
    "www.homeschool.com",
    "www.educents.com",
    "www.homeschoolbuyersco-op.org",
    "www.ikotoys.com",
    "picabooyearbooks.com",
    "beestar.org",
    "www.brainly.com",
    "www.bridgewayacademy.com",
    "bulbapp.com",
    "www.edu.buncee.com",
    "www.calverteducation.com",
    "classcraft.com",
    "www.classicalacademicpress.com",
    "www.edcoda.com",
    "www.EverBrightMedia.com",
    "www.foresttrailacademy.com",
    "globalstudentnetwork.com",
    "homelearninginstitute.com",
    "huehd.com",
    "www.ixl.com",
    "www.k12.com",
    "www.lessonplanet.com",
    "www.movingbeyondthepage.com",
    "www.myeducrate.org",
    "www.power-plus-learning.com",
    "questclubs.net",
    "www.songsforteaching.com",
    "study.com",
    "www.sycamoreacademy.com",
    "www.time4learning.com",
    "www.tjed.org",
    "OneYearNovel.com",
    "www.CoverStoryWriting.com",
    "www.easygrammar.com",
    "www.lindamoodbell.com",
    "readingeggs.com",
    "spellingyousee.com",
    "www.ReadingCare.com",
    "www.time4writing.com",
    "www.spellingcity.com",
    "www.conceptualacademy.com",
    "www.dadsworksheets.com",
    "mainstaymath.com",
    "www.mathusee.com",
    "nclab.com",
    "www.aop.com",
    "characterfirsteducation.com",
    "www.enlightiumacademy.com",
    "www.fpeusa.org",
    "www.memoriapress.com",
    "online.oakschristian.org",
    "foreignlanguagesforkids.com",
    "spanish.academy",
    "middleburyinteractive.com",
    "theadventurousmailbox.com",
    "www.aemoneyquests.com",
    "www.BonnieTerryLearning.com",
    "www.onlineg3.com",
    "www.virtualimagetherapy.com",
    "www.collegeprepgenius.com",
    "www.slader.com",
    "highschool.nebraska.edu",
};

//exclude google and facebook,instagram,snapchat,telegram who are prevent at most vpn-use country
const char* _utl_global_http_key_dictionary[] = {
    "bing",
    "office",
    "akadns",
    "akamai",
    "office365",
    "azureedge",
    "evernote",
    "att",
    "comcast",
    "yimg",
    "truste",
    "accounts",
    "attlocal",
    "cloudfront",
    "cloudflare",
    "googleapis",
    "googleplus",
    "weather",
    "financial",
    "finance",
    "descrip",
    "location",
    "security",
    "document",
    "handshake",
    "exchange",
    "account",
    "password",
    "credit",
    "creditcard",
    "paypal",
    "cash",
    "oil",
    "dollar",
    "balance",
    "duepay",
    "expire",
    "protect",
    "private",
    "storage",
    "apply",
    "resume",
    "cancel",
    "stop",
    "start",
    "holiday",
    "deposit",
    "flow",
    "cashflow",
    "bank",
    "transfer",
    "bill",
    "content",
    "fishing",
    "house",
    "domestic",
    "result",
    "query",
    "language",
    "region",
    "datetime",
    "zone",
    "host",
    "backup",
    "primary",
    "failover",
    "bugfix",
    "list",
    "contact",
    "service",
    "appoint",
    "record",
    "medical",
    "friend",
    "friendship",
    "desktop",
    "personal",
    "macair",
    "macpro",
    "IBM",
    "vacation",
    "complete",
    "retry",
    "timeout",
    "translate",
    "more",
    "page",
    "item",
    "setup",
    "register",
    "subscribe",
    "unsubscrib",
    "deliver",
    "book",
    "author",
    "applicate",
    "signature",
    "tax",
    "report",
    "profile",
    "group",
    "individual",
    "reduce",
    "increase",
    "decrease",
    "insert",
    "finish",
    "sohu",
    "sina",
    "360",
    "fortinet",
    "yahoo",
    "alipay",
    "sogou",
    "samsung",
    "live",
    "hao123",
    "calculate",
    "measure",
    "word",
    "powerpoint",
    "excel",
    "svncode",
    "chrome",
    "explore",
    "console",
    "universal",
    "colleague",
    "click",
    "close",
    "show",
    "next",
    "return",
    "study",
    "learn",
    "land",
    "space",
    "release",
    "publish",
    "update",
    "basketball",
    "football",
    "tennis",
    "swim",
    "window",
    "search",
    "view",
    "edit",
    "save",
    "sound",
    "reader",
    "example",
    "config",
    "todo",
    "downgrade",
    "upgrade",
    "score",
    "linux",
    "windows",
    "centos",
    "ubutone",
    "desk",
    "chair",
    "bed",
    "hotel",
    "room",
    "alarm",
    "options",
    "borrow",
    "rent",
    "party",
    "meeting",
    "class",
    "water",
    "cup",
    "tooth",
    "bag",
    "cookie",
    "shore",
    "t-shirt",
    "miss",
    "delay",
    "capture",
    "collect",
    "walk",
    "education",
    "computer",
    "garbage",
    "greenpower",
    "unite",
    "mcdonald",
    "restaurent",
    "distance",
    "load",
    "reload",
    "battery",
    "smoke",
    "cooler",
    "compete",
    "winner",
    "iphone",
    "android",
    "submit",
    "verify",
    "request",
    "form",
    "table",
    "sheet",
    "navigate",
    "redirect",
    "link",
    "pull",
    "recycle",
    "pay",
    "payment",
    "archive",
    "express",
};

//https://www.iana.org/assignments/media-types/media-types.xhtml
const char* _utl_common_http_mime_types[] = {
    "audio/midi",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "audio/aac",
    "image/bmp",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg",
    "image/tiff",
    "image/webp",
    "image/x-icon",
    "video/3gpp",
    "video/MP2T",
    "video/mp4",
    "video/mpeg",
    "video/ogg",
    "video/quicktime",
    "video/webm",
    "video/x-flv",
    "video/x-ms-wmv",
    "video/x-msvideo",
};

//for better peroramcne we encode '/' as well at end of name
const char * _utl_global_http_server_names[] = {
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

const char * _utl_global_http_method[] = {
    "GET",
    "PUT",
    "GET",
    "POST",
    "GET",
    "HEAD",
    "POST",
    "GET",
    "DELETE",
    "GET",
    "POST",
    "OPTIONS"
};

const char * _utl_global_http_languages[] = {
    "*",
    "en", //english
    "en-au", //English (Australia)
    "en-ca", //English (Canada)
    "en-us", //US english
    "en-nz", //new Zealand
    "en-gb", //England
    "de", //germany
    "zh", //china
    "fr", //french
    "ja", //japen
    "it", //italy
};

const char* _utl_global_http_mime_types[] = {
    "audio/midi",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "audio/aac",
    "image/bmp",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg",
    "image/tiff",
    "image/webp",
    "image/x-icon",
    "multipart/form-data",
    "video/3gpp",
    "video/MP2T",
    "video/mp4",
    "video/mpeg",
    "video/ogg",
    "video/quicktime",
    "video/webm",
    "video/x-flv",
    "video/x-ms-wmv",
    "video/x-msvideo",
};
std::vector<std::string> http_domains_list;

std::string string_utl::get_random_domain_name()
{
    #ifndef LINUX_PLATFORM
    //client may use customized domains list
    const std::string host_domain = get_random_domain();
    if(host_domain.empty() == false)
        return host_domain;
    #endif
    
    const int total_host_candicates = sizeof(_utl_global_http_edu_domains_dictionary) / sizeof(const char*);
    const std::string peer_host_name = _utl_global_http_edu_domains_dictionary[time_utl::get_random(total_host_candicates)];
    return peer_host_name;
}
std::string  string_utl::get_random_domain()
{
    const int total_host_candicates = (const int)http_domains_list.size();
    if(total_host_candicates <= 0)
        return std::string();
    
    const int random_index = time_utl::get_random(total_host_candicates);
    return http_domains_list[random_index];
}
const char *  test_domain_list[] = {
    "www.digikala.com",
    "www.graphiran.com",
    "www.parsonline.com",
    "www.aparat.com",
    "www.irancell.ir",
    "www.satiaisp.com",
    "www.bmn.ir",
    "www.irna.ir",
    "www.facenama.com",
    "www.ersiangfx.com",
    "www.jamejamonline.ir",
    "www.7sobh.com",
    "www.varzesh3.com",
    "www.parsian-bank.com",
    "www.film2movie.co",
    "www.eghtesadnews.com",
//    "www.163.com"

};
bool  string_utl::set_random_http_domains() {
    http_domains_list.clear();
    for(int i = 0; i < (sizeof(test_domain_list) / sizeof(const char*)); ++i)
    {
        http_domains_list.push_back(std::string(test_domain_list[i]));
    }
    return true;
}
std::string string_utl::get_random_http_mime_type()
{
    const int random_offset = time_utl::get_random(sizeof(_utl_global_http_mime_types) / sizeof(const char*));
    const std::string mime_type = _utl_global_http_mime_types[random_offset];
    return mime_type;
}
int32_t   string_utl::alpha_to_number(const std::string alpha_string) //decode alpha to number
{
    if(alpha_string.empty())
        return 0;
    
    int char_begin_pos = 0;
    const int max_chars_count = (const int)alpha_string.size();
    for(; char_begin_pos < max_chars_count; ++char_begin_pos)
    {
        if(alpha_string[char_begin_pos] != ' ')
            break;
        
        ++char_begin_pos;
    }
    if(char_begin_pos >= max_chars_count)
        return 0;
    
    bool is_negative = false; //default for positive
    if(alpha_string[char_begin_pos] == '-') //negative
    {
        is_negative = true;
        ++char_begin_pos;
    }
    else if(alpha_string[char_begin_pos] == '+') //positive
    {
        is_negative = false;
        ++char_begin_pos;
    }
    if(char_begin_pos >= max_chars_count)
        return 0;
 
    int32_t int_result = 0;
    const int32_t base = 26;
    for(; char_begin_pos < max_chars_count; ++char_begin_pos)
    {
        const int digit = alpha_string[char_begin_pos] - 'a';//must be [0,25]
        if( (digit < 0) || (digit >= base) )
            break;
        int_result = (base*int_result) + digit;
    }
    if(is_negative)
        return  -int_result;
    else
        return int_result;
}

bool  string_utl::digital_string(const std::string & test_string) //consist of number chars from 0-9
{
    if(test_string.empty())
        return false;
    
    if(test_string.find_first_not_of("0123456789") != std::string::npos)
        return false;
    
    return true;
}

