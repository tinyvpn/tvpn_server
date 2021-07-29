#ifndef __FILEUTL_H__
#define __FILEUTL_H__
#include <string>
#include "base.h"

class file_utl
{
public: //general writev/readv for file-handle that could be any handle of device(or system resource) or file
    //handle is usally set at non-block mode
    static int          writev(fd_handle_t handle,ju_buf_t * blocks_vector, int blocks_count);
    static int          readv(fd_handle_t handle,ju_buf_t * blocks_vector, int blocks_count);
    static int32_t      write(fd_handle_t handle,void * buffer, int32_t buffer_length);
    static int32_t      read(fd_handle_t handle,void * buffer, int32_t buffer_length);
    static int  read_file(const std::string file_path_name,std::string & file_content);
};
#endif
