#ifndef __SYSUTL_H__
#define __SYSUTL_H__

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>

#include "base.h"

class sys_utl
{
public:
    static int    open_tun_mq_devivce(std::string & dev_name,int request_queues,std::vector<fd_handle_t> & queue_handles);
    static int      open_tun_device(std::string & dev_name,bool persist_mode);
    static bool set_cloexec(int fd_handle);
    static std::string  kernel_version();
    static bool         kernel_version(int & version_major, int & version_feature,int & version_minor);
    static int   tun_dev_write(fd_handle_t tun_dev_handle, void* ptr_ip_packet, const int32_t packet_len);    
    static int   tun_dev_read(fd_handle_t tun_dev_handle,void* ptr_ip_buffer, const int32_t buffer_len);
};
#endif

