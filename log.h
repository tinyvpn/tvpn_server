#ifndef _LOG_H
#define _LOG_H
#include <string>
int OpenFile(const std::string& filename);
void INFO(const char *cmd, ...);
void DEBUG(const char *cmd, ...);
void ERROR(const char *cmd, ...);

#endif

