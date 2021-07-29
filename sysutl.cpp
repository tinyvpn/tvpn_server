#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <pthread.h>
#include <sched.h>

#ifdef MAC_PLATFORM
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_utun.h> //here defined _NET_IF_UTUN_H_
#elif defined(LINUX_PLATFORM)
    #include <linux/if.h>
    #include <linux/if_tun.h>
#endif
#include "sysutl.h"
#include "sockutl.h"
#include "stringutl.h"
#include "fileutl.h"

std::string sys_utl::kernel_version()
{
#ifdef __JU_LINUX_PLATFORM__
    struct utsname u_name;
    int result = uname( &u_name );
    if ( result < 0 )
        return "";
    
    std::string  releaseVersion = u_name.release;
    std::size_t pos = releaseVersion.find( '-', 0 );
    if ( pos != std::string::npos )
        releaseVersion = releaseVersion.substr( 0, pos );
    
    return releaseVersion;
#else
    return "";
#endif
}

bool sys_utl::kernel_version(int & major, int & feature,int & minor)
{
    major = 0;
    feature = 0;
    minor = 0;
    const std::string version_string = kernel_version();
    if(version_string.empty())
        return false;
    
    std::vector<std::string> parts;
    if(string_utl::split_string(version_string, '.', parts))
    {
        if(parts.size() == 3)
        {
            major = string_utl::StringToInt32(parts[0]);
            feature = string_utl::StringToInt32(parts[1]);
            minor = string_utl::StringToInt32(parts[2]);
            return true;
        }
    }
    return false;
}

#if defined(MAC_PLATFORM) //Mac OS and iOS
int mac_os_utun_open_new(struct ctl_info ctlInfo, int utun_num)
{
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
    {
        printf("sys_utl::mac_os_utun_open_new,fail to open system socket at errno:%d\n",errno);
        return -2;
    }
    if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
    {
        printf("sys_utl::mac_os_utun_open_new,fail to ioctl at errno:%d\n",errno);
        close(fd);
        return -2;
    }
    
    struct sockaddr_ctl sc = {0};
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = utun_num + 1;
    
    /* If the connect is successful, a utun%d device will be created, where "%d"
     * is (sc.sc_unit - 1) */
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
    {
        const int errno_int = errno;
        printf("sys_utl::mac_os_utun_open_new,fail to connect at errno:%d\n",errno_int);
        close(fd);
        return -1;
    }
    return fd;
}

int sys_utl::open_tun_device(std::string & dev_name,bool persist_mode)
{
    struct ctl_info ctlInfo;
    if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
        sizeof(ctlInfo.ctl_name))
    {
        printf("sys_utl::open_tun_device,fail to open utun kernel control for init_name(%s)\n",dev_name.c_str());
        return -1;
    }
    
    /* try to open first available utun device if no specific utun is requested */
    int utun_num =-1;
    if(dev_name.size() > 0)
    {
        //do protection if pass_in default name that may conflict with system name
        if(dev_name != "utun")
        {
            sscanf(dev_name.c_str(), "utun%d", &utun_num);
        }
    }
    int fd_device = -1;
    if(utun_num >= 0)
    {
        fd_device = mac_os_utun_open_new (ctlInfo, utun_num);
    }
    if(fd_device < 0)
    {
        for (utun_num = 0; utun_num < 255; utun_num++)
        {
            fd_device = mac_os_utun_open_new (ctlInfo, utun_num);
            /*get < 0 if early initalization failed */
            if (fd_device > 0 )
                break;
        }
    }
    if(fd_device < 0)
    {
        printf("sys_utl::open_tun_device,fail to create utun device for init_name(%s),errno:%d\n",dev_name.c_str(),errno);
        return fd_device; //error
    }
    
    /* Retrieve the assigned interface name. */
    char utunname[20] = {0};
    socklen_t utunname_len = sizeof(utunname);
    if(getsockopt(fd_device, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunname, &utunname_len))
    {
        printf("sys_utl::open_tun_device,fail to get utun interface name with fd(%d) and init_name(%s),errno:%d\n",fd_device,dev_name.c_str(),errno);
    }
    else
    {
        printf("sys_utl::open_tun_device,successful to get utun interface name(%s) with fd(%d) and init_name(%s)\n",utunname,fd_device,dev_name.c_str());
        dev_name = utunname; //return device name
    }
    socket_utl::set_nonblock(fd_device,true);
    sys_utl::set_cloexec(fd_device);
    return fd_device;
}
int   sys_utl::tun_dev_write(fd_handle_t tun_dev_handle, void* ptr_ip_packet, const int32_t packet_len)
{
    struct iovec iv[2];
    struct ip *iph = (struct ip *)ptr_ip_packet;
    
    uint32_t ip_type = 0;
    if(iph->ip_v == 6) //ipv6
        ip_type = htonl(AF_INET6);
    else
        ip_type = htonl(AF_INET);
    
    iv[0].iov_base = (char *)&ip_type;
    iv[0].iov_len  = sizeof(ip_type);
    iv[1].iov_base = ptr_ip_packet;
    iv[1].iov_len  = packet_len;
    
    /* /net/if_utun.h define _NET_IF_UTUN_H_
     * OpenBSD and Mac OS X when using utun
     * have a slightly incompatible TUN device from
     * the rest of the world, in that it prepends a
     * uint32 to the beginning of the IP header
     * to designate the protocol.
     * strip off this field on reads and
     * put it back on writes.
     */
    const int ret = (int)file_utl::writev(tun_dev_handle, (ju_buf_t*)iv, 2);
#ifdef _NET_IF_UTUN_H_
    if (ret > 0)
        return (ret > (ssize_t)sizeof(uint32_t)) ? (ret - sizeof(uint32_t)) : 0;
    else
        return ret;
#else
    return ret;
#endif

}
int   sys_utl::tun_dev_read(fd_handle_t tun_dev_handle,void* ptr_ip_buffer, const int32_t buffer_len)
{
    struct iovec iv[2];
    uint32_t ip_type = 0;
    iv[0].iov_base = &ip_type;
    iv[0].iov_len = sizeof(ip_type);
    iv[1].iov_base = ptr_ip_buffer;
    iv[1].iov_len = buffer_len;
    
    const int ret = (int)file_utl::readv(tun_dev_handle, (ju_buf_t*)iv, 2);
#ifdef _NET_IF_UTUN_H_
    if (ret > 0)
        return (ret > (ssize_t)sizeof(uint32_t)) ? (ret - sizeof(uint32_t)) : 0;
    else
        return ret;
#else
    return ret;
#endif

}
#elif defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
int sys_utl::open_tun_device(std::string & dev_name,bool persist_mode)
{
    return -1;
}
#else //at non_apple platform
int sys_utl::open_tun_device(std::string & dev_name,bool persist_mode)
{
    struct ifreq ifr;
    int fd, err;
    
    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
    {
        printf("fail to Open /dev/net/tun,error=%d\n",errno);
        return fd;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(dev_name.size() > 0)
    {
        //do protection if pass_in default name that may conflict with system name
        if( (dev_name != "tun") && (dev_name != "tap") )
        {
            strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);
        }
    }
    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) //try again
    {
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 )
        {
            close(fd);
            return err;
        }
    }
    dev_name = ifr.ifr_name; //get the final device name
    
    ioctl(fd, TUNSETNOCSUM,1); //disable checksum verification
    
    //int mode = IFF_MULTICAST;
    //ioctl(fd, TUNSIFMODE,mode);
    
    if(persist_mode)
    {
        if(ioctl(fd, TUNSETPERSIST, 1) < 0)
        {
            printf("sys_utl::open_tun_device,fail to ioctl with TUNSETPERSIST at errno:%d\n",errno);
        }
    }
    
    socket_utl::set_nonblock(fd,true);
    sys_utl::set_cloexec(fd);
    return fd;
}
int   sys_utl::tun_dev_write(fd_handle_t tun_dev_handle, void* ptr_ip_packet, const int32_t packet_len)
{
    return file_utl::write(tun_dev_handle,ptr_ip_packet,packet_len);
}
int   sys_utl::tun_dev_read(fd_handle_t tun_dev_handle, void* ptr_ip_buffer, const int32_t buffer_len)
{
    return file_utl::read(tun_dev_handle,ptr_ip_buffer,buffer_len);
}

#endif
bool sys_utl::set_cloexec(int fd_handle)
{
    if (fcntl(fd_handle, F_SETFD, FD_CLOEXEC) < 0)
    {
        return false;
    }

    return true;
}
int    sys_utl::open_tun_mq_devivce(std::string & dev_name,int request_queues,std::vector<fd_handle_t> & queue_handles)
{
    if(request_queues <= 0)
        request_queues = 1;
    else if(request_queues > 8) //no more than 8 queues for one tun device
        request_queues = 8;
    
    queue_handles.clear(); //reset first
    
    #if defined(LINUX_PLATFORM)
    int version_major = 0;
    int version_feature = 0;
    int version_minor = 0;
    if( (request_queues > 1) && (sys_utl::kernel_version(version_major,version_feature,version_minor)) )
    {
        if( (version_major > 3) || ((3 == version_major) && (version_feature >= 8)) ) //above 3.8.0
        {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
            /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
             *        IFF_TAP   - TAP device
             *
             *        IFF_NO_PI - Do not provide packet information
             *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
             */
            if(dev_name.size() > 0)
            {
                //do protection if pass_in default name that may conflict with system name
                if( (dev_name != "tun") && (dev_name != "tap") )
                {
                    strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);
                }
            }
            for (int i = 0; i < request_queues; i++) //start create queue handle
            {
                const int fd = open("/dev/net/tun", O_RDWR);//create one char-io-socket
                if(fd < 0)
                {
                    printf("fail to Open /dev/net/tun,error=%d,ret=%d,allocated:%d\n",errno,fd,(int)queue_handles.size());
                    for(std::vector<fd_handle_t>::iterator it = queue_handles.begin(); it != queue_handles.end(); ++it)
                    {
                        fd_handle_t alloc_handle = *it;
                        if(alloc_handle > 0)
                        {
                            close(alloc_handle);
                        }
                    }
                    queue_handles.clear();
                    break;
                }
                const int err = ioctl(fd, TUNSETIFF, (void *)&ifr); //link char-io-socket to tun device
                if(err < 0)
                {
                    printf("fail to link fd to tun device,error=%d,fd=%d,ret=%d,allocated:%d\n",errno,fd,err,(int)queue_handles.size());
                    for(std::vector<fd_handle_t>::iterator it = queue_handles.begin(); it != queue_handles.end(); ++it)
                    {
                        fd_handle_t alloc_handle = *it;
                        if(alloc_handle > 0)
                        {
                            close(alloc_handle);
                        }
                    }
                    queue_handles.clear();
                    break;
                }
                ioctl(fd, TUNSETNOCSUM,1); //disable checksum verification
                socket_utl::set_nonblock(fd,true);
                sys_utl::set_cloexec(fd);
                
                if(dev_name != ifr.ifr_name)
                    dev_name = ifr.ifr_name; //get the final device name
                
                queue_handles.push_back(fd);
            }
            if(queue_handles.size() > 0)
                return (int)queue_handles.size();
        }
    }
    #endif
    
    const int fd_handle = open_tun_device(dev_name, false);
    if(fd_handle > 0)
    {
        queue_handles.push_back(fd_handle);
        return 1;
    }
    return fd_handle;
}

