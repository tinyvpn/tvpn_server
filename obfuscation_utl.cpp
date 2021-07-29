#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>

#include "obfuscation_utl.h"
//ignore init_iv if it is 0;return false if fail
bool obfuscation_utl::encode(unsigned char* raw_data_ptr,const int raw_data_len,const uint32_t init_iv)
{
    if( (NULL == raw_data_ptr) || (raw_data_len <= 0 ) )
        return false;
    
    const uint32_t x_or_key = (raw_data_len * raw_data_len + raw_data_len + 1) * (raw_data_len + init_iv);
    
    uint32_t* raw_datae_4bytes = (uint32_t*)raw_data_ptr;
    const int n4bytes_len = raw_data_len >> 2;
    for(int i = 0; i < n4bytes_len; ++i)
    {
        raw_datae_4bytes[i] ^= x_or_key;
    }
    const int32_t left_bytes = raw_data_len - (n4bytes_len << 2);//must be 0,1,2,3
    for(int i = 0; i < left_bytes; ++i)
    {
        raw_data_ptr[(n4bytes_len << 2) + i] ^= ((unsigned char*)&x_or_key)[i];
    }
    return true;
}

//both encoded_data_len and init_iv must be exactly same as value used by xobfuscate,
bool obfuscation_utl::decode(unsigned char* encoded_data_ptr,const int encoded_data_len,const uint32_t init_iv)
{
    //that is 1-1 with same alogrithm
    return obfuscation_utl::encode(encoded_data_ptr,encoded_data_len,init_iv);
}

