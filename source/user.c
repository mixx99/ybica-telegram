#include "user.h"
#include "log.h"
#include "message.h"
#include "serialization.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

volatile int should_run = 1;

// Initializes the user.
// In future will read data from user.json or create it.
void init_user(User *user) { // TODO: full rework
  user->room = 0;
  char name[100] = "test-user\0";
  char digits[] = "0123456789";
  char number[3];
  number[0] = digits[rand() % 10];
  number[1] = digits[rand() % 10];
  number[2] = '\0';
  strcat(name, number);
  strncpy(user->name, name, USER_NAME_SIZE - 1);
  user->name[USER_NAME_SIZE - 1] = '\0';
  user->uuid = rand();
}

static inline int get_message(Message *message, int sockfd) {
  unsigned char message_data[MESSAGE_SERIALIZED_SIZE];
  int status = recv(sockfd, message_data, MESSAGE_SERIALIZED_SIZE, 0);
  if (status < 0) {
    print_error("Recv error");
    return -1;
  }
  deserialize_message(message, message_data);
  return 0;
}

// Listens other users in loop.
void listen_other_users(User *user) {
  int sockfd;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    print_error("Failed to create a socket to listen other users");
    abort();
  }
  int opt = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    print_error("Failed to bind a socket to listen other users");
    abort();
  }
  while (should_run) {
    Message message;
    if (get_message(&message, sockfd) < 0)
      continue;
    if (message.room != user->room)
      continue;
    if (message.sender_uuid == user->uuid)
      continue;
    print_message("%s: %s", message.sender_name,
                  message.text); // TODO: Make more beauty print message.
  }
  close(sockfd);
}

// Listens user input in loop.
// Send messages or execute commands like /pm *username* or /exit
void listen_user(User *user) {
  char *buffer = NULL;
  size_t buffer_size = MESSAGE_TEXT_LENGTH;
  buffer = (char *)malloc(buffer_size);
  Message message;
  message.room = 0; // The idea is - 0 room is general room.
  message.type = MESSAGE_TEXT;
  message.sender_uuid = user->uuid;
  strcpy(message.sender_name, user->name);
  while (should_run) {
    ssize_t readed = getline(&buffer, &buffer_size, stdin);
    buffer[readed] = '\0';
    strcpy(message.text, buffer);
    if (strcmp(buffer, "\n") == 0)
      continue;
    message.time = time(NULL);
    send_message(&message);
  }
  free(buffer);
}
