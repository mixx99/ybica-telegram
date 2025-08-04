#include "message.h"
#include "log.h"
#include "serialization.h"

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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
