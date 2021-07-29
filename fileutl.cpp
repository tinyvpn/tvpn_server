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
#include "fileutl.h"

int  file_utl::writev(fd_handle_t handle,ju_buf_t * blocks_vector, int blocks_count)
{
    if( (NULL == blocks_vector) || (0 == blocks_count) )
        return 0;

    ssize_t nReturn = 0;
    for(;;)
    {
        nReturn = ::writev(handle, (iovec*)blocks_vector, blocks_count);
        // repeat until success
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }

    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EAGAIN) || (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {
            if(nerr != EINTR)
                printf("file_utl::writev(%d) block(err id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
            
            errno = EAGAIN;
            return 0;
        }
        else
        {
            printf("file_utl::writev(%d) error(id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
            return -1;
        }
    }

    return static_cast <int>(nReturn);
}

int  file_utl::readv(fd_handle_t handle,ju_buf_t * blocks_vector, int blocks_count)
{
    if( (NULL == blocks_vector) || (0 == blocks_count) )
        return 0;
    
    ssize_t nReturn = 0;
    for(;;)
    {
        nReturn = ::readv(handle, (iovec*)blocks_vector, blocks_count);
        // repeat until success
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EAGAIN) || (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {

            if(nerr != EINTR)
                printf("file_utl::readv(%d) block(err id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
            
            errno = EAGAIN;
            return 0;
        }
        else
        {
            printf("file_utl::readv(%d) error(id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
            return -1;
        }
    }
    else if(0 == nReturn)
    {
        errno = 0; //reset to 0 to ensure it is different from the above error handle(convert errno to EAGAIN)
    }

    return static_cast <int>(nReturn);
}

int32_t file_utl::write(fd_handle_t handle,void * buffer, int32_t buffer_length)
{
    if( (NULL == buffer) || (0 == buffer_length) )
        return 0;
    
    ssize_t nReturn = 0;
    for(;;)
    {
        nReturn = ::write(handle, buffer, buffer_length);

        // repeat until success
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }

    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EAGAIN) || (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {

            if(nerr != EINTR)
                printf("file_utl::write(%d) block(err id=%d)\n",handle,nerr);

            errno = EAGAIN;
            return 0;
        }
        else if(nerr == EINVAL)
        {
//            printf("file_utl::write(%d) invalid param(err id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
            printf("file_utl::write(%d) invalid param(err id=%d)\n",handle,nerr);
            return 0; //but return real error code
        }
        else
        {
            printf("file_utl::write(%d) error(id=%d)\n",handle,nerr);
            return -1;
        }
    }

    return static_cast <int>(nReturn);
}

int32_t file_utl::read(fd_handle_t handle,void * buffer, int32_t buffer_length)
{
    if( (NULL == buffer) || (0 == buffer_length) )
        return 0;
    
    ssize_t nReturn = 0;
    for(;;)
    {
        nReturn = ::read(handle, buffer, buffer_length);
        // repeat until success
        if(nReturn < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }

    if(nReturn < 0)
    {
        const int nerr = errno;
        if( (nerr == EAGAIN) || (nerr == EWOULDBLOCK) || (nerr == EINTR) || (nerr == EINPROGRESS) || (nerr == EALREADY) )
        {
//            if(nerr != EINTR)
//                printf("file_utl::read(%d) block(err id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
           
            errno = EAGAIN;
            return 0;
        }
        else
        {
            printf("file_utl::read(%d) error(id=%d,descript=%s)\n",handle,nerr,strerror(nerr));
            return -1;
        }
    }
    else if(0 == nReturn)
    {
        errno = 0;
    }

    return static_cast <int>(nReturn);
}
int  file_utl::read_file(const std::string file_path_name,std::string & file_content)
{
    if(file_path_name.empty())
        return -3;
    
    FILE*  _file_handle = fopen(file_path_name.c_str(), "rb");
    if(0 == _file_handle)
    {
        printf("file_utl::read_file,fail to open file(%s) with errno(%d) and errstr(%s)",file_path_name.c_str(),errno,strerror(errno));
        return -2;
    }
    fseek(_file_handle, 0, SEEK_END);
    const int file_size = (int)ftell(_file_handle);
    fseek(_file_handle, 0, SEEK_SET); //seek to begin
    
    file_content.clear();
    file_content.resize(file_size);
    if(file_content.size() != file_size)
    {
        printf("file_utl::read_file,fail to reserved data size(%d)",file_size);
        fclose(_file_handle);
        return -1;
    }
    const size_t readed_size = fread((void*)file_content.data(), 1, file_size, _file_handle);
    if(readed_size <= 0)
        file_content.clear();
    else if(readed_size != file_size)
        file_content.resize(readed_size);
        
    fclose(_file_handle);
    return (int)readed_size;
}

