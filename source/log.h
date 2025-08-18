#ifndef LOG_H
#define LOG_H

#include "message.h"

void print_message(const char *message, ...);
void print_error(const char *message, ...);

void log_message(Message *message, uint32_t user_uuid, int is_private_message);
void print_history(uint32_t uuid);

void get_username(char *username);

void add_json_file(Message *message);
void update_json_file(Message *message);
void remove_json_file(Message *message);

void get_stucked_message(Message *message);

#endif // LOG_H
