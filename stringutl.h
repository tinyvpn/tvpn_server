#ifndef __STRING_UTL__
#define __STRING_UTL__
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include "base.h"

class string_utl
{
public:
    static bool  digital_string(const std::string & test_string); //test whether consist of number chars from 0-9    
    static int32_t       StringToInt32(const std::string & string_value);
    static uint32_t      StringToUInt32(const std::string & string_value);
    static int64_t       StringToInt64(const std::string & string_value);
    static uint64_t      StringToUInt64(const std::string & string_value);
    static std::string   Int32ToString(const int32_t int32value);
    static std::string   UInt32ToString(const uint32_t uint32value);
    static std::string   Int64ToString(const int64_t int64value);
    static std::string   UInt64ToString(const uint64_t uint64value);
    
    //split_string remove split_char of each setion,and split into std::vector<std::string>
    static bool  split_string(const std::string & input,const char split_char,std::vector<std::string> & values);
    static bool  split_string(const std::string & input,const std::string & boundry_letters,std::vector<std::string> & values);
    
    //split_string2 keep the "split_char" for each section,and split into std::vector<std::string>
    static bool  split_string2(const std::string & input,const char split_char,std::vector<std::string> & values);
    static std::string HexEncode(const std::string& str);
    static std::string HexDecode(const std::string& str);
    //alpha code: map ['a','b',... 'x','y','z']  to [0,1,...25]
    //e.g. 25= "z",26 = "ba",261 = "kb"
    static std::string   number_to_alpha(const int32_t number);
    static int32_t       alpha_to_number(const std::string alpha_string); //decode alpha to number;

    static std::string get_random_domain_name();
    static std::string  get_random_domain();
    static bool set_random_http_domains();
    static std::string get_random_http_mime_type();    
};
#endif
