#ifndef MESSAGE_H
#define MESSAGE_H

#include "user.h"

// std
#include <stdint.h>
#include <time.h>

#define MESSAGE_TEXT_LENGTH 1024
#define MESSAGE_SERIALIZED_SIZE                                                \
  sizeof(uint32_t) * 4 + USER_NAME_SIZE + MESSAGE_TEXT_LENGTH
#define PORT 5555

enum MESSAGE_TYPE { MESSAGE_FILE, MESSAGE_TEXT };

typedef struct {
  uint32_t sender_uuid;
  char sender_name[USER_NAME_SIZE];
  uint32_t room;
  uint32_t type;
  uint32_t time;
  char text[MESSAGE_TEXT_LENGTH];
} Message;

void send_message(Message *message);

#endif // MESSAGE_H
