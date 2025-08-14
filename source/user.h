#ifndef USER_H
#define USER_H

#include <stdint.h>

#define USER_NAME_SIZE 200
#define USER_LOCAL_IP_SIZE 100

typedef struct {
  char name[USER_NAME_SIZE];
  uint32_t uuid;
  uint32_t room;
  char local_ip[USER_LOCAL_IP_SIZE];
  uint32_t port;
} User;

void init_user(User *user);
void listen_user(User *user);
void listen_other_users(User *user);

#endif // USER_H
