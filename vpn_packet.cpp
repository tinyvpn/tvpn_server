#include "vpn_packet.h"
#include <assert.h>
#include <string.h>
VpnPacket::VpnPacket(char* buf,int32_t nInitOffset, const int32_t nInitCapacity)
{
    _front_offset = nInitOffset;
    _back_offset = nInitOffset;    
    data_ptr = (uint8_t*)buf;
    capacity = nInitCapacity;
    alloc_policy = 1;
}

VpnPacket::VpnPacket(const int32_t nInitCapacity)
{
    capacity = nInitCapacity;
    _front_offset = get_capacity() >> 2;
    _back_offset = _front_offset;
    data_ptr = (uint8_t*)malloc(nInitCapacity);
    alloc_policy = 0;
}
VpnPacket::VpnPacket(int32_t nInitOffset,const int32_t nInitCapacity)
{
    _front_offset = nInitOffset;
    _back_offset = nInitOffset;    
    data_ptr = (uint8_t*)malloc(nInitCapacity);
    capacity = nInitCapacity;
    alloc_policy = 0;
}
VpnPacket::~VpnPacket(){
    if (alloc_policy == 0)
        free(data_ptr);
}
uint8_t*   VpnPacket::data() const
{
    if(NULL == data_ptr)
        return NULL;
    return  (data_ptr + _front_offset);
}
int32_t   VpnPacket::get_capacity() const
{
    return capacity;
}
int32_t   VpnPacket::remain_size() const
{
    if (capacity <= _back_offset)
        return 0;
    return capacity - _back_offset;
}

//Note: write to the next avaiable data position like FIFO
int32_t   VpnPacket::push_front(uint8_t* pPtr, const uint32_t nPushBufSize)
{
    if(0 == nPushBufSize)
        return 0;
    
    const int32_t nCurOffset = front_offset() - nPushBufSize;
    if(nCurOffset < 0)
    {
        INFO("Jumemh_t::push_front,front_off(%d) < nPushBufSize(%d),back_off(%d)",_front_offset,nPushBufSize,_back_offset);
        assert(nCurOffset >= 0);
    }
    if(pPtr != NULL) //(NULL pPtr do just reserved)
        memcpy(data_ptr + nCurOffset, pPtr, nPushBufSize);
    
    _front_offset = nCurOffset;
    return nPushBufSize;

}
int32_t   VpnPacket::push_back(uint8_t* pPtr, const uint32_t nPushBufSize)
{
    if(0 == nPushBufSize)
        return 0;
    
    if(pPtr != NULL) //(NULL pPtr do just reserved)
        memcpy(data_ptr + _back_offset, pPtr, nPushBufSize);
    
    _back_offset += nPushBufSize;
    return nPushBufSize;
}
int32_t   VpnPacket::size() const
{
    if(_back_offset > _front_offset)
        return (_back_offset - _front_offset);
    return 0;
}
bool  VpnPacket::reset() //reset try to reuse the allocated memory for next time,use carefuly
{
    _front_offset = get_capacity() >> 2;
    _back_offset = _front_offset;
    return true;
}
int32_t   VpnPacket::front_offset() const
{
    return _front_offset;
}

int32_t   VpnPacket::back_offset() const
{
    return _back_offset;
}
int32_t    VpnPacket::set_front_offset(const int32_t offset)
{
    _front_offset = offset;
    return offset;
}

int32_t    VpnPacket::set_back_offset(const int32_t offset)
{
    _back_offset = offset;
    return offset;
}

