#ifndef __TIMEUTL_H__
#define __TIMEUTL_H__

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>

#include "base.h"

class time_utl
{
public:
    static uint32_t get_random(uint32_t mode);    
    static uint32_t get_randomu();    
    static std::string  gmt_http_date_time(); //convert GMT date and time to HTTP format    
    static std::string  gmt_http_date_time(const int time_offet);    
	//return seconds from local base time
	static time_t		localtime();
	static std::string	local_date();	   //conver local date to string
	static std::string	local_date_time(); //convert local date and hours/minutes to string
	static time_t		gmttime();	//return how many seconds since 1970/01/01 and 00.00.00 at local timezone
	static std::string	gmt_date();   //conver gmt date to string
	static std::string	gmt_date_time(); //convert GMT date and hours/minutes to string
	static std::string	gmt_date(time_t rawtime);   //conver gmt date to string
	static std::string	gmt_date_time(time_t rawtime); //convert GMT date and hours/minutes to string
	
};
#endif
