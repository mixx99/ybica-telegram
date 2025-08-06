#include "message.h"
#include "log.h"
#include "serialization.h"
#include "user.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

volatile int should_send_file = 1;
static pthread_mutex_t should_send_file_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t get_file_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline int get_should_send_file();

static inline int get_should_send_file() {
  pthread_mutex_lock(&should_send_file_mutex);
  int value = should_send_file;
  pthread_mutex_unlock(&should_send_file_mutex);
  return value;
}

void set_should_send_file(int value) {
  pthread_mutex_lock(&should_send_file_mutex);
  should_send_file = value;
  pthread_mutex_unlock(&should_send_file_mutex);
}

// Gets and parse a file from message.
void get_file(Message *message) {
  pthread_mutex_lock(&get_file_mutex);
  FILE *file = NULL;
  char path[100] = "./downloads/";
  strncat(path, message->sender_name, USER_NAME_SIZE);
  if (message->type == MESSAGE_FILE_START) {
    print_message("Start to download the file %s", message->sender_name);
    file = fopen(path, "wb");
  }
  if (message->type == MESSAGE_FILE_MID)
    file = fopen(path, "ab");
  if (message->type == MESSAGE_FILE_END)
    print_message("File was successfully downloaded. The sender is: %s",
                  message->sender_name);
  if (file == NULL && message->type != MESSAGE_FILE_END) {
    print_error(
        "get_file: Failed to get a file: %s. Check the downloads folder",
        message->sender_name);
    pthread_mutex_unlock(&get_file_mutex);
    return;
  }
  if (file != NULL && message->type != MESSAGE_FILE_END)
    fwrite(message->text, 1, message->room, file);

  if (file != NULL)
    fclose(file);
  pthread_mutex_unlock(&get_file_mutex);
}

// Sends a file via send_private_message function.
void send_private_file(User *receiver, User *me, char *path) {
  set_should_send_file(1);
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    print_error("Failed to send and open a file %s", path);
    return;
  }
  int packet_number = 1;
  Message message = {0};

  char *filename = strrchr(path, '/');
  if (filename != NULL)
    filename++;
  strncpy(message.sender_name, filename, USER_NAME_SIZE);

  print_message("Sending a file %s", filename);
  while (get_should_send_file()) {
    uint32_t readed = fread(message.text, 1, MESSAGE_TEXT_LENGTH, file);
    if (readed == 0)
      break;
    message.room = readed;
    message.time = time(NULL);
    message.sender_uuid = me->uuid;
    if (packet_number == 1)
      message.type = MESSAGE_FILE_START;
    if (packet_number > 1)
      message.type = MESSAGE_FILE_MID;
    send_private_message(receiver, &message);
    packet_number++;
  }
  memset(&message, 0, sizeof(message));
  message.sender_uuid = me->uuid;
  strncpy(message.sender_name, me->name, USER_NAME_SIZE);
  message.time = time(NULL);
  message.type = MESSAGE_FILE_END;
  send_private_message(receiver, &message);
  if (get_should_send_file())
    print_message("File was sent successfully");
  fclose(file);
  set_should_send_file(1);
}

// Gets and deserializes message.
int get_message(Message *message, int sockfd) {
  unsigned char message_data[sizeof(*message)];
  int status = recv(sockfd, message_data, sizeof(message_data), 0);
  if (status < 0) {
    print_error("Recv error");
    return -1;
  }
  deserialize_message(message, message_data);
  return 0;
}

// Sends private TCP message to receiver using his local ip and port.
void send_private_message(User *receiver, Message *message) {
  int sockfd;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    print_error("Failed to create a socket in private message");
    abort();
  }
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(receiver->port);
  sockaddr.sin_addr.s_addr = inet_addr(receiver->local_ip);

  if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
    print_error("Failed to connect to receiver");
    return;
  }

  unsigned char message_data[sizeof(*message)], *ptr;
  ptr = serialize_message(message, message_data);
  send(sockfd, message_data, ptr - message_data, 0);
  close(sockfd);
}

// Sends message to everyone using UDP broadcast.
void send_message(Message *message) {
  int sockfd;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    print_error("Failed to create a socket in send_message function");
    abort();
  }
  int broadcast = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                 sizeof(broadcast)) < 0) {
    print_error("Setsockopt failed in send_message");
    close(sockfd);
    abort();
  }
  struct sockaddr_in sockaddr = {0};
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(PORT);
  sockaddr.sin_addr.s_addr = inet_addr("255.255.255.255");

  unsigned char message_data[sizeof(*message)], *ptr;
  ptr = serialize_message(message, message_data);
  int sent = sendto(sockfd, message_data, ptr - message_data, 0,
                    (struct sockaddr *)&sockaddr, sizeof(sockaddr));
  if (sent < 0) {
    print_error("Failed to send a message");
    return;
  }
  close(sockfd);
}
