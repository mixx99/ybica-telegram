#ifndef MESSAGE_H
#define MESSAGE_H

#include "user.h"

#include <stdint.h>

#define MESSAGE_TEXT_LENGTH 8192
#define PORT 5555

enum MESSAGE_TYPE {
  MESSAGE_TEXT, // Regular message with text.

  // System messages with info about user inside.
  // message.room = user. port, message.text = user.local_ip
  MESSAGE_SYSTEM_JOIN,
  MESSAGE_SYSTEM_EXIT,
  MESSAGE_SYSTEM_ABOUT_ME,

  MESSAGE_FILE_START,
  MESSAGE_FILE_MID,
  MESSAGE_FILE_END,
  // Decline file transfer if sender isn't trusted.
  MESSAGE_FILE_DECLINE
};

typedef struct {
  uint32_t sender_uuid;
  char sender_name[USER_NAME_SIZE];
  uint32_t room; // TODO: Rename it. It's not a room anymore. It's like context_value now.
                 // MESSAGE_TEXT use it?
                 // MESSAGE_SYSTEM_ uses it as user.port
                 // MESSAGE_FILE_ uses it as buffer size.
  uint32_t type;
  uint32_t time;
  char text[MESSAGE_TEXT_LENGTH];
} Message;

void send_message(Message *message);
void send_private_message(User *receiver, Message *message);
void send_private_file(User *receiver, User *me, char *path);

void get_file(Message *message);
int get_message(Message *message, int sockfd);

void set_should_send_file(int value);

#endif // MESSAGE_H
