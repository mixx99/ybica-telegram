#ifndef MESSAGE_H
#define MESSAGE_H

#include "user.h"

#include <stdint.h>

#define MESSAGE_TEXT_LENGTH 1024
#define PORT 5555

enum MESSAGE_TYPE {
  MESSAGE_FILE,
  MESSAGE_TEXT,
  MESSAGE_SYSTEM_JOIN,
  MESSAGE_SYSTEM_EXIT,
  MESSAGE_SYSTEM_ABOUT_ME
};

typedef struct {
  uint32_t sender_uuid;
  char sender_name[USER_NAME_SIZE];
  uint32_t room;
  uint32_t type;
  uint32_t time;
  char text[MESSAGE_TEXT_LENGTH];
} Message;

void send_message(Message *message);
void send_private_message(User *receiver, Message *message);

#endif // MESSAGE_H
