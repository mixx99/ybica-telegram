#ifndef USER_H
#define USER_H

#include <stdint.h>

#define USER_NAME_SIZE 50

typedef struct {
  char name[USER_NAME_SIZE];
  uint32_t uuid;
  uint32_t room;
} User;

void init_user(User *user);
void listen_user(User *user);
void listen_other_users(User *user);

#endif // USER_H
