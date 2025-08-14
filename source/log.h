#ifndef LOG_H
#define LOG_H

#include "message.h"

void print_message(const char *message, ...);
void print_error(const char *message, ...);

void add_json_file(Message *message);
void update_json_file(Message *message);
void remove_json_file(Message *message);

void get_stucked_message(Message *message);

#endif // LOG_H
