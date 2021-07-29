#include "log.h"
#include <stdarg.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>

#include <string>
FILE* fp=NULL;
uint32_t log_level = 1;
int OpenFile(const std::string& filename) {
    fp = NULL;
    fp = fopen(filename.c_str(), "a");
    if (fp == NULL) 
        return 1;
    return 0;
}
void ERROR(const char *cmd, ...) {
    if (log_level > 2)
        return;
    if (fp == NULL)
        return;
    time_t t;
    struct tm *p;
    struct timeval tv;  
    int millsec;

    t = time(NULL);
    p = localtime(&t);
    gettimeofday(&tv, NULL);
    millsec = (int)(tv.tv_usec / 1000);
    fprintf(fp, "%02d:%02d:%02d:%03d-", p->tm_hour, p->tm_min, p->tm_sec, millsec);    
    fprintf(fp, "%d[ERROR]", getpid());  
    va_list args;       
    va_start(args,cmd); 
    vfprintf(fp, cmd,args);  
    va_end(args);       
    fprintf(fp, "\n");  
    fflush(fp);
} 

void INFO(const char *cmd, ...) {
    if (log_level > 1)
        return;
    if (fp == NULL)
        return;
    time_t t;
    struct tm *p;
    struct timeval tv;  
    int millsec;

    t = time(NULL);
    p = localtime(&t);
    gettimeofday(&tv, NULL);
    millsec = (int)(tv.tv_usec / 1000);
    fprintf(fp, "%02d:%02d:%02d:%03d-", p->tm_hour, p->tm_min, p->tm_sec, millsec);    
    fprintf(fp, "%d[INFO]", getpid());  
    va_list args;       
    va_start(args,cmd); 
    vfprintf(fp, cmd,args);  
    va_end(args);       
    fprintf(fp, "\n");  
    fflush(fp);
} 
void DEBUG(const char *cmd, ...) {
    if (log_level > 0)
        return;
    if (fp == NULL)
        return;
    time_t t;
    struct tm *p;
    struct timeval tv;  
    int millsec;

    t = time(NULL);
    p = localtime(&t);
    gettimeofday(&tv, NULL);
    millsec = (int)(tv.tv_usec / 1000);
    fprintf(fp, "%02d:%02d:%02d:%03d-", p->tm_hour, p->tm_min, p->tm_sec, millsec);    
    fprintf(fp, "%d[DEBUG]", getpid());  
    va_list args;       
    va_start(args,cmd); 
    vfprintf(fp, cmd,args);  
    va_end(args);       
    fprintf(fp, "\n");  
    fflush(fp);
} 

