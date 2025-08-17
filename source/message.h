#ifndef MESSAGE_H
#define MESSAGE_H

#include "user.h"

#include <openssl/types.h>

#include <stdint.h>

#define MESSAGE_TEXT_LENGTH 8192
#define PORT 5555

enum MESSAGE_TYPE {
  MESSAGE_TEXT, // Regular message with text inside.

  // System messages with info about user inside.
  // message.context_value = user. port, message.text = user.local_ip
  MESSAGE_SYSTEM_JOIN,
  MESSAGE_SYSTEM_EXIT,
  MESSAGE_SYSTEM_ABOUT_ME,

  MESSAGE_FILE_START,
  MESSAGE_FILE_MID,
  MESSAGE_FILE_END,
  MESSAGE_FILE_RESUME_REQUEST,
  MESSAGE_FILE_DECLINE
};

typedef struct {
  uint32_t sender_uuid;
  char sender_name[USER_NAME_SIZE];
  uint32_t context_value;
  /*
   * MESSAGE_SYSTEM_* use context_value as user.port
   * MESSAGE_FILE_MID use context_value as buffer size.
   * MESSAGE_FILE_END use context_value as CRC value.
   * MESSAGE_FILE_RESUME_REQUEST use context_value as packet number to resume.
   */
  uint32_t type;
  uint32_t time;
  char text[MESSAGE_TEXT_LENGTH];
} Message;

void send_message(Message *message);
void send_private_message(User *receiver, Message *message);
void send_private_file(User *receiver, User *me, char *path, int packet_number);

void get_file(Message *message);
int get_message(Message *message, int sockfd);
int get_ssl_message(Message *message, SSL *ssl);

void set_should_send_file(int value);

#endif // MESSAGE_H
