#include "message.h"
#include "crc.h"
#include "log.h"
#include "serialization.h"
#include "user.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

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
  char path[250] = "./downloads/";
  strncat(path, message->sender_name, USER_NAME_SIZE);
  if (message->type == MESSAGE_FILE_START) {
    print_message("Start to download the file %s", message->sender_name);
    file = fopen(path, "wb");
    fclose(file); // Just clear or create the file.
    add_json_file(message);
    pthread_mutex_unlock(&get_file_mutex);
    return;
  }
  if (message->type == MESSAGE_FILE_MID) {
    file = fopen(path, "ab");
    update_json_file(message);
  }
  if (message->type == MESSAGE_FILE_END) {
    remove_json_file(message);
    if (message->context_value == get_crc(path))
      print_message("File was successfully downloaded.");
    else
      print_error("Failed to download a file");
  }

  if (file == NULL && message->type != MESSAGE_FILE_END) {
    print_error("get_file: Failed to get a file: %s. Check the "
                "downloads folder",
                message->sender_name);
    pthread_mutex_unlock(&get_file_mutex);
    return;
  }
  if (file != NULL && message->type != MESSAGE_FILE_END)
    fwrite(message->text, 1, message->context_value, file);

  if (file != NULL)
    fclose(file);
  pthread_mutex_unlock(&get_file_mutex);
}

// Sends a file via send_private_message function.
void send_private_file(User *receiver, User *me, char *path,
                       int start_packet_number) {
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

  if (start_packet_number == 0) {
    Message start_message = {0};
    strncpy(start_message.sender_name, filename, USER_NAME_SIZE);
    strncpy(start_message.text, path, MESSAGE_TEXT_LENGTH);
    start_message.sender_uuid = me->uuid;
    start_message.type = MESSAGE_FILE_START;
    send_private_message(receiver, &start_message);
  }

  print_message("Sending a file %s", filename);
  while (get_should_send_file()) {
    uint32_t readed = fread(message.text, 1, MESSAGE_TEXT_LENGTH, file);
    if (readed == 0)
      break;
    if (packet_number < start_packet_number) {
      packet_number++;
      continue;
    }
    message.context_value = readed;
    message.time = time(NULL);
    message.sender_uuid = me->uuid;
    message.type = MESSAGE_FILE_MID;
    send_private_message(receiver, &message);
    packet_number++;
  }
  message.time = time(NULL);
  message.type = MESSAGE_FILE_END;
  message.context_value = get_crc(path);
  send_private_message(receiver, &message);
  if (get_should_send_file())
    print_message("File was sent successfully");
  fclose(file);
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
  return status;
}

int get_ssl_message(Message *message, SSL *ssl) {
  unsigned char buffer[sizeof(*message)];
  int result = 0;
  result = SSL_read(ssl, buffer, sizeof(buffer));
  if (result < 0) {
    print_error("Failed to SSL_read");
    return -1;
  }
  deserialize_message(message, buffer);
  return result;
}

// Sends private TCP message to receiver using his local ip and port.
void send_private_message(User *receiver, Message *message) {
  int sockfd;
  SSL_CTX *context = NULL;
  SSL *ssl = NULL;

  context = SSL_CTX_new(TLS_client_method());
  if (!context) {
    print_error("SSL_CTX_new failed");
    goto cleanup;
  }
  if (SSL_CTX_use_certificate_file(context, "crypto/user.crt",
                                   SSL_FILETYPE_PEM) != 1) {
    print_error("Failed to load user certificate");
    goto cleanup;
  }
  if (SSL_CTX_use_PrivateKey_file(context, "crypto/user.key",
                                  SSL_FILETYPE_PEM) != 1) {
    print_error("Failed to load user private key");
    goto cleanup;
  }
  if (SSL_CTX_load_verify_locations(context, "crypto/ca.crt", NULL) != 1) {
    print_error("Failed to load CA certificate");
    goto cleanup;
  }

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    print_error("Failed to create a socket in private message");
    goto cleanup;
  }
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(receiver->port);
  sockaddr.sin_addr.s_addr = inet_addr(receiver->local_ip);

  if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
    print_error("Failed to connect to receiver");
    goto cleanup;
  }

  ssl = SSL_new(context);
  if (!ssl) {
    print_error("SSL_new failed");
    goto cleanup;
  }
  SSL_set_fd(ssl, sockfd);

  if (SSL_connect(ssl) != 1) {
    print_error("SSL_connect failed");
    goto cleanup;
  }

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    print_error("Certificate verification failed");
    goto cleanup;
  }

  unsigned char message_data[sizeof(*message)], *ptr;
  ptr = serialize_message(message, message_data);

  SSL_write(ssl, message_data, ptr - message_data);
cleanup:
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (sockfd >= 0)
    close(sockfd);
  if (context)
    SSL_CTX_free(context);
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
