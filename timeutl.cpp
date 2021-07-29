#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>
#include <time.h>
#include <unistd.h>

#include "timeutl.h"
const int max_srand_seed_count = 32;
static uint32_t g_srand_seed[max_srand_seed_count] = {0}; //32 random seed to improve the random performance

//quickly generate Pseudorandom number
uint32_t time_utl::get_randomu()
{
    uint32_t rand_value = 0;
    const uint32_t stack_address_of_rand_value = (uint32_t)((uint64_t)&rand_value);
    
    uint32_t & rand_seed = g_srand_seed[stack_address_of_rand_value % max_srand_seed_count];
    if((rand_seed % 256) == 0) //random reset the seed
    {
        //note:srand and rand() has glibc lock inside, so is negative for multiple-thread
        //refer stdlib/random.c
        srand((unsigned)time(NULL));
        rand_seed = rand();
    }
    rand_value = (214013*rand_seed+2531011);
    rand_seed = rand_value;
    
    return rand_value;
}

uint32_t time_utl::get_random(uint32_t mode)
{
    const uint32_t randvalue = get_randomu();
    if(0 == mode)
        return randvalue;
    else
        return (randvalue % mode);
}
std::string time_utl::gmt_http_date_time()
{
    time_t rawtime;
    time(&rawtime); //return how many seconds since 1970/01/01 and 00.00.00
    struct tm tminfo = *::gmtime(&rawtime); //conver to GMT time information(tm)
    
    char szFormatedString[256];
    strftime(szFormatedString, sizeof(szFormatedString), "%a, %d %b %Y %H:%M:%S %Z", &tminfo);
    return std::string(szFormatedString);
}

std::string time_utl::gmt_http_date_time(const int time_offet)
{
    time_t rawtime;
    time(&rawtime); //return how many seconds since 1970/01/01 and 00.00.00
    rawtime += time_offet;
    struct tm tminfo = *::gmtime(&rawtime); //conver to GMT time information(tm)
    
    char szFormatedString[256];
    strftime(szFormatedString, sizeof(szFormatedString), "%a, %d %b %Y %H:%M:%S %Z", &tminfo);
    return std::string(szFormatedString);
}
//return seconds from local base time
time_t time_utl::localtime()
{
    struct tm* timeinfo = 0;
    time_t rawtime;
    
    time(&rawtime);
    timeinfo = ::localtime(&rawtime);
    return mktime(timeinfo);
}

std::string time_utl::local_date()
{
    time_t t = time(NULL);
    struct tm tm = *::localtime(&t);
    
    char szFormatedString[1024];
    snprintf(szFormatedString,1024,"%d-%d-%d",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    
    return std::string(szFormatedString);
}

std::string time_utl::local_date_time()
{
    time_t t = time(NULL);
    struct tm tm = *::localtime(&t);
    
    char szFormatedString[1024];
    snprintf(szFormatedString,1024,"%d-%d-%d %d:%d:%d",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    
    return std::string(szFormatedString);
}
//return seconds from UTC base time
time_t time_utl::gmttime()
{
    struct tm* timeinfo = 0;
    time_t rawtime;
    
    time(&rawtime); //return how many seconds since 1970/01/01 and 00.00.00 at local timezone
    timeinfo = ::gmtime(&rawtime); //conver to GMT time information(tm)
    return mktime(timeinfo);//convert again to see how many seconds since 1970/01/01 and 00.00.00
}

std::string time_utl::gmt_date()
{
    time_t rawtime;
    time(&rawtime); //return how many seconds since 1970/01/01 and 00.00.00
    struct tm tminfo = *::gmtime(&rawtime); //conver to GMT time information(tm)
    
    char szFormatedString[1024];
    snprintf(szFormatedString,1024,"%d-%d-%d",tminfo.tm_year + 1900, tminfo.tm_mon + 1, tminfo.tm_mday);
    
    return std::string(szFormatedString);
}

std::string time_utl::gmt_date_time()
{
    time_t rawtime;
    time(&rawtime); //return how many seconds since 1970/01/01 and 00.00.00
    struct tm tminfo = *::gmtime(&rawtime); //conver to GMT time information(tm)

    char szFormatedString[1024];
    snprintf(szFormatedString,1024,"%d-%d-%d %d:%d:%d",tminfo.tm_year + 1900, tminfo.tm_mon + 1, tminfo.tm_mday, tminfo.tm_hour, tminfo.tm_min, tminfo.tm_sec);
    
    return std::string(szFormatedString);
}
std::string time_utl::gmt_date(time_t rawtime)
{
    struct tm tminfo = *::gmtime(&rawtime); //conver to GMT time information(tm)
    
    char szFormatedString[1024];
    snprintf(szFormatedString,1024,"%d-%02d-%02d",tminfo.tm_year + 1900, tminfo.tm_mon + 1, tminfo.tm_mday);
    
    return std::string(szFormatedString);
}

std::string time_utl::gmt_date_time(time_t rawtime)
{
    struct tm tminfo = *::gmtime(&rawtime); //conver to GMT time information(tm)

    char szFormatedString[1024];
    snprintf(szFormatedString,1024,"%d-%02d-%02d %02d:%02d:%02d",tminfo.tm_year + 1900, tminfo.tm_mon + 1, tminfo.tm_mday, tminfo.tm_hour, tminfo.tm_min, tminfo.tm_sec);
    
    return std::string(szFormatedString);
}

