#ifndef __VPN_PACKET_H__
#define __VPN_PACKET_H__
#include "base.h"
class VpnPacket {
public:
    explicit VpnPacket(const int32_t nInitCapacity);
    explicit VpnPacket(int32_t nInitOffset,const int32_t nInitCapacity);
    explicit VpnPacket(char* buf,int32_t nInitOffset, const int32_t nInitCapacity);
    ~VpnPacket();
    uint8_t *  data() const;         //point to real data position(already apply the front_offset)
    int32_t    size() const;         //how many bytes are stored
    int32_t    get_capacity() const;     //malloc memory
    int32_t    remain_size() const;     //malloc memory
    bool       reset();  //similar as init but reset try to reuse the used memory for next time,use carefuly
    //Note: write to the next avaiable data position like FIFO, just change offset if pPtr is NULL
    //Note: ask_mem_barrier support single-thread write, and another single thread read safe
    int32_t    push_front(uint8_t* pPtr, const uint32_t nSize);
    int32_t    push_back(uint8_t* pPtr, const uint32_t nSize);
    int32_t    front_offset() const; //front offset to data
    int32_t    back_offset() const;  //back offset, [front,back) is the data range
    int32_t    set_front_offset(const int32_t offset);
    int32_t    set_back_offset(const int32_t offset);

private:
    uint32_t        _front_offset;    //front data offset
    uint32_t        _back_offset;     //back offset of data[front_offset,backoffset)    
    uint8_t*      data_ptr;
    int32_t       capacity;        //total memory size of the data    
    uint8_t       alloc_policy;    //refer enum_mem_handle_alloc_policy
};
#endif
