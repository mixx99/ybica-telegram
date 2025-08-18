#include "user.h"
#include "crypto.h"
#include "log.h"
#include "message.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define ACTIVE_USERS_SIZE 256
#define TRUSTED_USERS_SIZE ACTIVE_USERS_SIZE
#define CHECK_STUCKED_FILES_DELAY                                              \
  20 // Be sure that this value is more than MAX_DELAY in log.c

static User *global_user = NULL;
static int is_global_chat_on = 1;

static volatile int should_run = 1;
static User active_users[ACTIVE_USERS_SIZE] = {0};
static User trusted_users[TRUSTED_USERS_SIZE] = {0};

static int tcp_listen_ready = 0;
static int udp_listen_ready = 0;
static pthread_mutex_t listen_ready_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t global_chat_mutex = PTHREAD_MUTEX_INITIALIZER;

static int socket_tcp = 0;
static int socket_udp = 0;
static int socket_localip = 0;

static inline void add_active_user(Message *message);
static inline void add_trusted_user(char *name);
static inline void remove_active_user(Message *message);
static inline void remove_trusted_user(char *name);
static inline void show_active_users();
static inline void show_trusted_users();
static inline User *find_user(uint32_t uuid);
static inline User *find_user_by_name(char *name);
static inline User *find_trusted_user(char *name);
static inline User *find_trusted_user_by_uuid(uint32_t uuid);
static inline void get_local_ip(char *buffer, size_t buffer_size);
static inline void send_info_join_to_everyone(User *user);
static inline void send_info_about_me_to_user(uint32_t uuid, User *me);
static inline void parse_user_input(User *user, Message *message, char *buffer,
                                    size_t buffer_size);
static inline void parse_message(Message *message, User *user, int is_private);
static inline void parse_file_message(Message *message, User *me);
static inline void *listen_other_users_tcp(void *args);
static inline void *listen_other_users_udp(void *args);
static inline void print_help();
static inline void print_welcome_message(User *user);
static inline void *check_download_files(void *user_arg);
static inline void destroy_user(User *user);
static inline void sigint_handler(int dummy);
static inline void set_global_chat_status(int value);
static inline int get_global_chat_status();

static inline void set_global_chat_status(int value) {
  pthread_mutex_lock(&global_chat_mutex);
  is_global_chat_on = value;
  pthread_mutex_unlock(&global_chat_mutex);
}

static inline int get_global_chat_status() {
  int result;
  pthread_mutex_lock(&global_chat_mutex);
  result = is_global_chat_on;
  pthread_mutex_unlock(&global_chat_mutex);
  return result;
}
// Adds user to active_users.
static inline void add_active_user(Message *message) {
  User user;
  strncpy(user.name, message->sender_name, USER_NAME_SIZE - 1);
  user.name[USER_NAME_SIZE - 1] = '\0';
  user.room = 0;
  strncpy(user.local_ip, message->text, USER_LOCAL_IP_SIZE - 1);
  user.local_ip[USER_LOCAL_IP_SIZE - 1] = '\0';
  user.uuid = message->sender_uuid;
  user.port = message->context_value;

  for (int i = 0; i < ACTIVE_USERS_SIZE; ++i) {
    if (active_users[i].uuid == user.uuid)
      return;
  }

  for (int i = 0; i < ACTIVE_USERS_SIZE; ++i) {
    if (active_users[i].uuid == 0) {
      active_users[i] = user;
      return;
    }
  }
  print_error("Failed to add a user %s.", message->sender_name);
}

// Adds user to trusted users.
static inline void add_trusted_user(char *name) {
  User *user = find_user_by_name(name);
  if (user == NULL) {
    print_error("Failed to add user %s to trusted users.", name);
    return;
  }
  for (int i = 0; i < TRUSTED_USERS_SIZE; ++i)
    if (trusted_users[i].uuid == user->uuid) {
      print_message("User %s already trusted", name);
      return;
    }
  for (int i = 0; i < TRUSTED_USERS_SIZE; ++i) {
    if (trusted_users[i].uuid == 0) {
      trusted_users[i] = *user;
      print_message("Now %s is trusted user", name);
      return;
    }
  }
  print_error("Failed to add user %s to trusted users.", name);
}

// Removes user from active_users.
static inline void remove_active_user(Message *message) {
  for (int i = 0; i < ACTIVE_USERS_SIZE; ++i) {
    if (active_users[i].uuid == message->sender_uuid) {
      memset(&active_users[i], 0, sizeof(active_users[i]));
      return;
    }
  }
  print_error("Failed to remove user %s.", message->sender_name);
}

// Removes user from trusted users.
static inline void remove_trusted_user(char *name) {
  User *user = find_user_by_name(name);
  if (user == NULL) {
    print_error("Failed to remove trusted user %s.", name);
    return;
  }
  for (int i = 0; i < TRUSTED_USERS_SIZE; ++i) {
    if (trusted_users[i].uuid == user->uuid) {
      memset(&trusted_users[i], 0, sizeof(trusted_users[i]));
      return;
    }
  }
  print_error("Failed to remove trusted user %s.", name);
}

// Finds user in active_users.
static inline User *find_user(uint32_t uuid) {
  for (int i = 0; i < ACTIVE_USERS_SIZE; ++i)
    if (active_users[i].uuid == uuid)
      return &active_users[i];
  return NULL;
}

// Finds and returns user by name in active_users.
static inline User *find_user_by_name(char *name) {
  for (int i = 0; i < ACTIVE_USERS_SIZE; ++i) {
    if (active_users[i].uuid != 0 &&
        strncmp(active_users[i].name, name, USER_NAME_SIZE) == 0)
      return &active_users[i];
  }
  return NULL;
}

// Return's pointer to user if he's trusted.
static inline User *find_trusted_user_by_uuid(uint32_t uuid) {
  for (int i = 0; i < TRUSTED_USERS_SIZE; ++i)
    if (trusted_users[i].uuid == uuid)
      return &trusted_users[i];
  return NULL;
}

// Return's pointer to user if he's trusted.
static inline User *find_trusted_user(char *name) {
  for (int i = 0; i < TRUSTED_USERS_SIZE; ++i)
    if (strncmp(trusted_users[i].name, name, USER_NAME_SIZE) == 0)
      return &trusted_users[i];
  return NULL;
}

// Prints all active_users.
static inline void show_active_users() {
  print_message("Current active users:");
  for (int i = 0; i < ACTIVE_USERS_SIZE; ++i) {
    if (active_users[i].uuid != 0)
      print_message("%d.%s", i + 1, active_users[i].name);
  }
}

// Shows all trusted users.
static inline void show_trusted_users() {
  print_message("Current trusted users:");
  for (int i = 0; i < TRUSTED_USERS_SIZE; ++i) {
    if (trusted_users[i].uuid != 0)
      print_message("%d. %s", i + 1, trusted_users[i].name);
  }
}

// Catch the SIGINT signal.
static inline void sigint_handler(int dummy) {
  destroy_user(global_user);
  destroy_SSL();
  abort();
}

// Initializes the user.
void init_user(User *user) {
  global_user = user;
  initialize_SSL();
  signal(SIGINT, sigint_handler);
  if (verify_user_certificate() < 0) {
    print_error("Something went wrong with sertificate");
    abort();
  } else {
    print_message("Certificate ok");
  }
  user->room = 0;
  get_username(user->name);
  user->uuid = get_user_uuid_from_cert();
  user->port = PORT + rand() % 50000;
  char buffer[USER_LOCAL_IP_SIZE];
  get_local_ip(buffer, USER_LOCAL_IP_SIZE);
  strncpy(user->local_ip, buffer, USER_LOCAL_IP_SIZE);
  print_welcome_message(user);
}

static inline void print_welcome_message(User *user) {
  print_message("Welcome to chat.\n"
                "Your name: %s\n"
                "Your room: %u\n"
                "Your uuid: %u\n"
                "Your local ip: %s\n"
                "Your port: %u\n"
                "Use /help for commands\n",
                user->name, user->room, user->uuid, user->local_ip, user->port);
}

/*
 * Sends message which type is MESSAGE_SYSTEM_JOIN with info about user after
 * his first initialization. Message.text = user.local_ip,
 * Message.context_value = user.port. Should be used once.
 */
static inline void send_info_join_to_everyone(User *user) {
  Message message = {0};
  strncpy(message.sender_name, user->name, USER_NAME_SIZE - 1);
  message.sender_name[USER_NAME_SIZE - 1] = '\0';
  message.context_value = user->port;
  message.sender_uuid = user->uuid;
  strncpy(message.text, user->local_ip, USER_LOCAL_IP_SIZE - 1);
  message.text[USER_LOCAL_IP_SIZE - 1] = '\0';
  message.time = time(NULL);
  message.type = MESSAGE_SYSTEM_JOIN;
  send_message(&message);
}

/*
 * Sends info about user to receiver using private_message.
 * Message.text = user.local_ip, Message.context_value = user.port.
 */
static inline void send_info_about_me_to_user(uint32_t uuid, User *me) {
  User *receiver = find_user(uuid);
  if (receiver == NULL) {
    print_error("Failed to find user to send him message");
    return;
  }
  Message message = {0};
  message.sender_uuid = me->uuid;
  strncpy(message.sender_name, me->name, USER_NAME_SIZE);
  strncpy(message.text, me->local_ip, USER_LOCAL_IP_SIZE);
  message.type = MESSAGE_SYSTEM_ABOUT_ME;
  message.time = time(NULL);
  message.context_value = me->port;

  send_private_message(receiver, &message);
}

// Gets local user ip to buffer.
static inline void get_local_ip(char *buffer, size_t buffer_size) {
  socket_localip = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_localip < 0) {
    print_error("Failed to get local ip");
    return;
  }

  struct sockaddr_in fake_addr;
  memset(&fake_addr, 0, sizeof(fake_addr));
  fake_addr.sin_family = AF_INET;
  fake_addr.sin_port = htons(80);
  inet_pton(AF_INET, "8.8.8.8", &fake_addr.sin_addr);

  if (connect(socket_localip, (struct sockaddr *)&fake_addr,
              sizeof(fake_addr)) < 0) {
    print_error("Failed to get local ip");
    close(socket_localip);
    return;
  }

  struct sockaddr_in local_addr;
  socklen_t addr_len = sizeof(local_addr);
  if (getsockname(socket_localip, (struct sockaddr *)&local_addr, &addr_len) <
      0) {
    close(socket_localip);
    return;
  }

  inet_ntop(AF_INET, &local_addr.sin_addr, buffer, buffer_size);
  close(socket_localip);
}

static inline void parse_file_message(Message *message, User *me) {
  User *user = find_trusted_user_by_uuid(message->sender_uuid);
  if (user == NULL &&
      message->type ==
          MESSAGE_FILE_START) // Two conditions are required, since we can
                              // accidentally send two or more messages like
                              // MESSAGE_FILE_DECLINE and print duplicate
                              // messages to the user.
  {
    user = find_user(message->sender_uuid);
    if (user == NULL) {
      print_error("Something went wrong. Someone tried to send you a file. "
                  "Can't find a file sender in active users.");
      return;
    }
    print_message(
        "%s tried to send you a file. Failed because he isn't a trusted "
        "user.(Hint: use /trust <name> to add him to trusted users)",
        user->name);
    Message message_fail_receive = {0};
    message_fail_receive.type = MESSAGE_FILE_DECLINE;
    message_fail_receive.sender_uuid = me->uuid;
    strncpy(message_fail_receive.sender_name, me->name, USER_NAME_SIZE);
    message_fail_receive.time = time(NULL);
    send_private_message(user, &message_fail_receive);
    return;
  }
  if (user == NULL)
    return;
  get_file(message);
}

// Parses message.
static inline void parse_message(Message *message, User *user, int is_private) {
  if (message->sender_uuid == user->uuid)
    return;
  if (message->type == MESSAGE_SYSTEM_JOIN) {
    print_message("[SYS]New member: %s", message->sender_name);
    add_active_user(message);
    send_info_about_me_to_user(message->sender_uuid, user);
    return;
  }
  if (message->type == MESSAGE_SYSTEM_ABOUT_ME) {
    add_active_user(message);
    return;
  }
  if (message->type == MESSAGE_SYSTEM_EXIT) {
    print_message("[SYS]%s left.", message->sender_name);
    remove_active_user(message);
    return;
  }
  if (message->type == MESSAGE_FILE_START ||
      message->type == MESSAGE_FILE_MID || message->type == MESSAGE_FILE_END) {
    parse_file_message(message, user);
    return;
  }
  if (message->type == MESSAGE_FILE_DECLINE) {
    print_error("Failed to send a file. User doesn't trust you.");
    set_should_send_file(0);
    return;
  }
  if (message->type == MESSAGE_FILE_RESUME_REQUEST) {
    User *request_user = find_user(message->sender_uuid);
    print_message(
        "%s request a resume downloading a file %s.\nTo resume uploading a "
        "file please copy and paste the command \"/resume %s %u %s \"",
        request_user->name, message->sender_name, request_user->name,
        message->context_value, message->text);
  }
  if (message->context_value != user->room)
    return;
  if (message->type != MESSAGE_TEXT)
    return;
  if (is_private)
    print_message("[PRIVATE MESSAGE]");

  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  if (get_global_chat_status() ||
      is_private) /* If we listen global chat or it's a private message */
    print_message("[%02d:%02d:%02d] %s: %s", t->tm_hour, t->tm_min, t->tm_sec,
                  message->sender_name, message->text);
  if (is_private)
    log_message(message, message->sender_uuid, 1);
  else
    log_message(message, message->sender_uuid, 0);
}

// Listens other users using UDP broadcast.
static inline void *listen_other_users_udp(void *args) {
  User *user = (User *)args;
  socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_udp < 0) {
    print_error("Failed to create a socket to listen other users");
    abort();
  }
  int opt = 1;
  setsockopt(socket_udp, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(socket_udp, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    print_error("Failed to bind a socket to listen other users");
    abort();
  }
  pthread_mutex_lock(&listen_ready_mutex);
  udp_listen_ready = 1;
  if (udp_listen_ready && tcp_listen_ready)
    send_info_join_to_everyone(user);
  pthread_mutex_unlock(&listen_ready_mutex);
  while (should_run) {
    Message message;
    if (get_message(&message, socket_udp) < 0)
      continue;
    parse_message(&message, user, 0);
  }
  close(socket_udp);
  return NULL;
}

// Listens other users using TCP private messages.
static inline void *listen_other_users_tcp(void *args) {
  signal(SIGPIPE, SIG_IGN);
  int should_abort = 0;
  User *user = (User *)args;
  SSL_CTX *context = NULL;
  SSL *ssl = NULL;
  context = SSL_CTX_new(TLS_server_method());

  if (context == NULL) {
    print_error("SSL_CTX_new failed");
    abort();
  }

  if (SSL_CTX_use_certificate_file(context, "crypto/user.crt",
                                   SSL_FILETYPE_PEM) != 1) {
    print_error("Failed to load user certificate");
    should_abort = 1;
    goto cleanup;
  }
  if (SSL_CTX_use_PrivateKey_file(context, "crypto/user.key",
                                  SSL_FILETYPE_PEM) != 1) {
    print_error("Failed to load user private key");
    should_abort = 1;
    goto cleanup;
  }

  if (SSL_CTX_load_verify_locations(context, "crypto/ca.crt", NULL) != 1) {
    print_error("Failed to load CA certificate");
    should_abort = 1;
    goto cleanup;
  }

  SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     NULL);

  socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_tcp < 0) {
    print_error("Failed to create TCP socket");
    should_abort = 1;
    goto cleanup;
  }
  int opt = 1;
  setsockopt(socket_tcp, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(user->port);
  sockaddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(socket_tcp, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
    print_error("Failed to bind TCP socket");
    close(socket_tcp);
    should_abort = 1;
    goto cleanup;
  }
  if (listen(socket_tcp, 10) < 0) {
    print_error("Failed to listen TCP socket");
    should_abort = 1;
    goto cleanup;
  }
  pthread_mutex_lock(&listen_ready_mutex);
  tcp_listen_ready = 1;
  if (tcp_listen_ready && udp_listen_ready)
    send_info_join_to_everyone(user);
  pthread_mutex_unlock(&listen_ready_mutex);
  while (should_run) {
    int client_sock = accept(socket_tcp, NULL, NULL);
    if (client_sock < 0) {
      print_error("Accept error in TCP socket");
      continue;
    }
    ssl = SSL_new(context);
    if (!ssl) {
      print_error("SSL_new failed");
      continue;
    }
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) != 1) {
      print_error("SSL_accept failed");
      continue;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
      print_error("User certificate verification failed");
      continue;
    }
    Message message;
    get_ssl_message(&message, ssl);
    parse_message(&message, user, 1);
    close(client_sock);
  }
cleanup:
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (socket_tcp >= 0)
    close(socket_tcp);
  if (context)
    SSL_CTX_free(context);
  return NULL;
}

// Checks every CHECK_STUCKED_FILES_DELAY seconds the data/files.json for
// stucked message.
static inline void *check_download_files(void *user_arg) {
  User *me = (User *)user_arg;
  Message stucked_message = {0};
  while (should_run) {
    sleep(CHECK_STUCKED_FILES_DELAY);
    memset(&stucked_message, 0, sizeof(stucked_message));
    get_stucked_message(&stucked_message);
    if (stucked_message.sender_uuid == 0)
      continue;
    User *receiver = find_user(stucked_message.sender_uuid);
    if (receiver == NULL) // Maybe offline.
      continue;
    Message request_message;
    request_message.sender_uuid = me->uuid;
    request_message.context_value = stucked_message.context_value;
    request_message.type = MESSAGE_FILE_RESUME_REQUEST;
    strncpy(request_message.text, stucked_message.text, MESSAGE_TEXT_LENGTH);
    strncpy(request_message.sender_name, stucked_message.sender_name,
            USER_NAME_SIZE);
    request_message.time = time(NULL);
    send_private_message(receiver, &request_message);
    print_message("Sended a request to resume download a file to %s.",
                  receiver->name);
  }
  return NULL;
}

// Listens other users in loop.
void listen_other_users(User *user) {
  pthread_t worker_listen_udp, worker_listen_tcp, worker_check_downloads;
  pthread_create(&worker_listen_udp, NULL,
                 (void *(*)(void *))listen_other_users_tcp, user);
  pthread_create(&worker_listen_tcp, NULL,
                 (void *(*)(void *))listen_other_users_udp, user);
  pthread_create(&worker_check_downloads, NULL,
                 (void *(*)(void *))check_download_files, user);
  pthread_join(worker_listen_tcp, NULL);
  pthread_join(worker_listen_udp, NULL);
  pthread_join(worker_check_downloads, NULL);
}

// Parses user input from stdin.
static inline void parse_user_input(User *user, Message *message, char *buffer,
                                    size_t buffer_size) {
  ssize_t readed = getline(&buffer, &buffer_size, stdin);
  buffer[readed] = '\0';
  if (strncmp(buffer, "\n", buffer_size) == 0)
    return;
  if (strncmp(buffer, "/members\n", buffer_size) == 0) {
    show_active_users();
    return;
  }
  if (strncmp(buffer, "/pm ", 4) == 0) {
    char *name = strtok(buffer + 4, " ");
    char *text = strtok(NULL, "\n");
    if (name == NULL || text == NULL) {
      print_error("Use /pm <name> <text>");
      return;
    }
    User *receiver = find_user_by_name(name);
    if (receiver == NULL) {
      print_error("Failed to find a user %s", name);
      return;
    }
    strncpy(message->text, text, MESSAGE_TEXT_LENGTH);
    send_private_message(receiver, message);
    return;
  }
  if (strncmp(buffer, "/resume ", 8) == 0) {
    char *name = strtok(buffer + 8, " ");
    char *packet_number_str = strtok(NULL, " ");
    char *path = strtok(NULL, "\n");

    if (name == NULL || packet_number_str == NULL || path == NULL) {
      print_error("Please copy the correct string or use /resume <name> "
                  "<packet-number> <path-to-file>");
      return;
    }
    uint32_t packet_number = atoi(packet_number_str);
    User *receiver = find_user_by_name(name);
    print_message("Resuming the uploading.");
    send_private_file(receiver, user, path, packet_number + 1);
    return;
  }
  if (strncmp(buffer, "/general", 8) == 0) {
    if (get_global_chat_status() != 0) {
      print_message("General chat disabled");
      set_global_chat_status(0);
    } else {
      print_message("General chat enabled");
      set_global_chat_status(1);
    }
    return;
  }
  if (strncmp(buffer, "/history ", 9) == 0) {
    char *name = strtok(buffer + 9, "\n");
    if (name == NULL) {
      print_error("Use /history <username>");
      return;
    }
    User *other_user = find_user_by_name(name);
    if (other_user == NULL) {
      print_error("Failed to find a user %s", name);
      return;
    }
    print_message("History with user %s", name);
    print_history(other_user->uuid);
    return;
  }
  if (strncmp(buffer, "/sendg ", 7) == 0) {
    char *token = strtok(buffer + 7, " ");
    if (token == NULL) {
      print_error("Use /sendg <number-of-users> <users> <message>");
      return;
    }
    int number = atoi(token);
    if (number <= 0) {
      print_error("Invalid number of users");
      return;
    }
    User *receivers[number];
    for (int i = 0; i < number; i++) {
      token = strtok(NULL, " ");
      if (token == NULL) {
        print_error("Not enough usernames provided");
        return;
      }
      User *u = find_user_by_name(token);
      if (u == NULL) {
        print_error("Failed to find a user %s", token);
        return;
      }
      receivers[i] = u;
    }
    char *text = strtok(NULL, "\n");
    if (text == NULL) {
      print_error("Message text missing");
      return;
    }
    strncpy(message->text, text, MESSAGE_TEXT_LENGTH);
    for (int i = 0; i < number; i++) {
      send_private_message(receivers[i], message);
    }
    return;
  }
  if (strncmp(buffer, "/sendfile ", 10) == 0) {
    char *name = strtok(buffer + 10, " ");
    char *file = strtok(NULL, "\n");
    if (name == NULL || file == NULL) {
      print_error("Use /sendfile <name> <path-to-file>");
      return;
    }
    User *receiver = find_user_by_name(name);
    if (receiver == NULL) {
      print_error("Failed to find a user %s", name);
      return;
    }
    send_private_file(receiver, user, file, 0);
    return;
  }
  if (strncmp(buffer, "/trust ", 7) == 0) {
    char *name = strtok(buffer + 7, "\n");
    add_trusted_user(name);
    return;
  }
  if (strncmp(buffer, "/untrust ", 9) == 0) {
    char *name = strtok(buffer + 9, "\n");
    remove_trusted_user(name);
    return;
  }
  if (strncmp(buffer, "/trusted\n", buffer_size) == 0) {
    show_trusted_users();
    return;
  }
  if (strncmp(buffer, "/help\n", buffer_size) == 0) {
    print_help();
    return;
  }
  strncpy(message->text, buffer, buffer_size);
  message->time = time(NULL);
  send_message(message);
}

// Prints help message.
static inline void print_help() {
  print_message(
      "/help -- for help message\n"
      "/pm <name> <text> -- for private message\n"
      "/members -- for list of current members\n"
      "/trust <user> -- Trust the user. He will be able to send you files.\n"
      "/untrust <user> -- Stop trust user. He won't be able to send you "
      "files.\n"
      "/trusted -- List of your trusted users.\n"
      "/sendfile <user> <path-to-file> -- Send a file to user. Need to be a "
      "trusted user.\n"
      "/general -- Enable/Disable general chat.\n"
      "/history <username> -- Prints the history with user.\n"
      "/sendg <Number-of-users> <Users> <Text> -- Sends a message to group of "
      "users.\n");
}

// Sends to everyone message with type MESSAGE_SYSTEM_EXIT.
void destroy_user(User *user) {
  Message message = {0};
  message.sender_uuid = user->uuid;
  message.type = MESSAGE_SYSTEM_EXIT;
  message.time = time(NULL);
  strncpy(message.sender_name, user->name, USER_NAME_SIZE);
  should_run = 0;
  send_message(&message);
}

// Listens user input in loop.
void listen_user(User *user) {
  char *buffer = NULL;
  size_t buffer_size = MESSAGE_TEXT_LENGTH;
  buffer = (char *)malloc(buffer_size);
  Message message = {0};
  message.type = MESSAGE_TEXT;
  message.sender_uuid = user->uuid;
  strncpy(message.sender_name, user->name, USER_NAME_SIZE);
  while (should_run) {
    parse_user_input(user, &message, buffer, buffer_size);
  }
  free(buffer);
}
