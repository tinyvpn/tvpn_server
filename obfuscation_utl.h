#ifndef __OBFUSCATION_UTL_H__
#define __OBFUSCATION_UTL_H__
#include <unistd.h>
#include "base.h"
//to avoid problem,obfuscation_utl object must be temp  that can not be persisten hold by new/malloc
class obfuscation_utl
{
public:
    //ignore init_iv if it is 0;return false if fail.
    static   bool encode(unsigned char* raw_data_ptr,const int raw_data_len,const uint32_t init_iv);//obfuscate must paired with decode
    //both encoded_data_len and init_iv must be exactly same as value used by encode
    static   bool decode(unsigned char* encoded_data_ptr,const int encoded_data_len,const uint32_t init_iv);
};
#endif
