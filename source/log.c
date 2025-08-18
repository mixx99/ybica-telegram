#include "log.h"
#include "message.h"
#include "user.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cJSON/cJSON.h>

#define JSON_FILES_PATH "data/files.json"
#define JSON_USER_PATH "data/user.json"
#define USER_FILENAMES_SIZE 100
#define MAX_DELAY 5

pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_files_json = PTHREAD_MUTEX_INITIALIZER;

static inline cJSON *load_json_file(const char *path);
static inline int save_json_file(const char *path, cJSON *json);
static inline void request_username(char *username);

static inline cJSON *load_json_file(const char *path) {
  pthread_mutex_lock(&mutex_files_json);
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    print_error("Failed to open %s", path);
    pthread_mutex_unlock(&mutex_files_json);
    return cJSON_CreateObject();
  }

  fseek(file, 0, SEEK_END);
  int len = ftell(file);
  rewind(file);

  char *data = malloc(len + 1);
  if (data == NULL) {
    print_error("Malloc failed to load json file");
    fclose(file);
    pthread_mutex_unlock(&mutex_files_json);
    return NULL;
  }
  fread(data, 1, len, file);
  data[len] = '\0';
  fclose(file);

  cJSON *json = cJSON_Parse(data);
  free(data);

  if (json == NULL) {
    pthread_mutex_unlock(&mutex_files_json);
    return cJSON_CreateObject();
  }
  pthread_mutex_unlock(&mutex_files_json);
  return json;
}

void print_history(uint32_t uuid) {
  char filename[USER_FILENAMES_SIZE];
  char path[USER_FILENAMES_SIZE] = "data/\0";
  sprintf(filename, "%u.txt", uuid);
  strcat(path, filename);
  FILE *file = fopen(path, "r");
  if (!file) {
    print_error("No history found for user");
    return;
  }
  char line[1024];
  while (fgets(line, sizeof(line), file))
    print_message("%s\n", line);
  fclose(file);
}

void log_message(Message *message, uint32_t user_uuid, int is_private_message) {
  char filename[USER_FILENAMES_SIZE];
  char path[USER_FILENAMES_SIZE] = "data/\0";
  if (is_private_message)
    snprintf(filename, sizeof(filename), "%u", user_uuid);
  else
    strncpy(filename, "general", USER_FILENAMES_SIZE);
  strcat(filename, ".txt");
  strcat(path, filename);
  FILE *file = fopen(path, "a");
  if (file == NULL) {
    print_error("Failed to open a file to log message");
    return;
  }
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  fprintf(file, "[%02d:%02d:%02d] %s: %s\n", t->tm_hour, t->tm_min, t->tm_sec,
          message->sender_name, message->text);
  fclose(file);
}

static inline int save_json_file(const char *path, cJSON *json) {
  char *out = cJSON_Print(json);
  if (out == NULL)
    return -1;

  pthread_mutex_lock(&mutex_files_json);
  FILE *file = fopen(path, "w");
  if (file == NULL) {
    free(out);
    pthread_mutex_unlock(&mutex_files_json);
    return -1;
  }

  fprintf(file, "%s", out);
  fclose(file);
  free(out);
  pthread_mutex_unlock(&mutex_files_json);
  return 0;
}

void add_json_file(Message *message) {
  cJSON *json = load_json_file(JSON_FILES_PATH);

  cJSON *file_obj = cJSON_CreateObject();
  cJSON_AddStringToObject(file_obj, "status", "in-progress");
  cJSON_AddNumberToObject(file_obj, "sender_uuid", message->sender_uuid);
  cJSON_AddNumberToObject(file_obj, "last_packet_number", 0);
  cJSON_AddStringToObject(file_obj, "path_to_file", message->text);
  cJSON_AddNumberToObject(file_obj, "last_update", time(NULL));

  cJSON_AddItemToObject(json, message->sender_name, file_obj);

  save_json_file(JSON_FILES_PATH, json);
  cJSON_Delete(json);
}

// Requests the username from stdin.
static inline void request_username(char *username) {
  print_message("Please enter your name:");
  scanf("%s", username);
  cJSON *json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "name", username);
  save_json_file(JSON_USER_PATH, json);
  cJSON_Delete(json);
}

// Copy name from user.json to username.
void get_username(char *username) {
  cJSON *json = load_json_file(JSON_USER_PATH);
  if (!json) {
    request_username(username);
    return;
  }
  cJSON *name_obj = cJSON_GetObjectItem(json, "name");
  if (!name_obj || !cJSON_IsString(name_obj)) {
    cJSON_Delete(json);
    request_username(username);
    return;
  }
  strncpy(username, name_obj->valuestring, USER_NAME_SIZE - 1);
  username[USER_NAME_SIZE - 1] = '\0';
  cJSON_Delete(json);
}

void update_json_file(Message *message) {
  cJSON *json = load_json_file(JSON_FILES_PATH);
  cJSON *file_obj = cJSON_GetObjectItem(json, message->sender_name);
  if (file_obj != NULL) {
    cJSON *pkt = cJSON_GetObjectItem(file_obj, "last_packet_number");
    if (pkt != NULL && cJSON_IsNumber(pkt)) {
      pkt->valuedouble += 1;
      cJSON_SetNumberValue(pkt, pkt->valueint + 1);
    }
    cJSON_ReplaceItemInObject(file_obj, "last_update",
                              cJSON_CreateNumber(time(NULL)));
  }
  save_json_file(JSON_FILES_PATH, json);
  cJSON_Delete(json);
}

void remove_json_file(Message *message) {
  cJSON *json = load_json_file(JSON_FILES_PATH);
  cJSON_DeleteItemFromObject(json, message->sender_name);
  save_json_file(JSON_FILES_PATH, json);
  cJSON_Delete(json);
}

void get_stucked_message(
    Message *message) { // TODO: Can we get a few stucked files?
  cJSON *json = load_json_file(JSON_FILES_PATH);
  if (!json)
    return;

  uint32_t now = time(NULL);

  cJSON *file_item = NULL;
  cJSON_ArrayForEach(file_item, json) {
    cJSON *last_update = cJSON_GetObjectItem(file_item, "last_update");
    if (last_update == NULL || !cJSON_IsNumber(last_update))
      continue;

    if (now - (uint32_t)last_update->valuedouble > MAX_DELAY) {
      cJSON *path_to_file = cJSON_GetObjectItem(file_item, "path_to_file");
      if (path_to_file == NULL || !cJSON_IsString(path_to_file))
        continue;

      cJSON *uuid = cJSON_GetObjectItem(file_item, "sender_uuid");
      if (uuid == NULL || !cJSON_IsNumber(uuid))
        continue;

      cJSON *last_packet_number =
          cJSON_GetObjectItem(file_item, "last_packet_number");
      if (last_packet_number == NULL || !cJSON_IsNumber(last_packet_number))
        continue;

      strncpy(message->sender_name, file_item->string,
              USER_NAME_SIZE); // filename
      strncpy(message->text, path_to_file->valuestring, MESSAGE_TEXT_LENGTH);
      message->sender_uuid = uuid->valuedouble;
      message->context_value = last_packet_number->valueint;
      cJSON_SetNumberValue(last_update,
                           time(NULL)); // Update time.
      save_json_file(JSON_FILES_PATH, json);
      cJSON_Delete(json);
      return;
    }
  }
  cJSON_Delete(json);
}

// Safe print to stdout with mutex lock inside.
void print_message(const char *message, ...) {
  pthread_mutex_lock(&mutex_print);
  va_list arg_list;
  va_start(arg_list, message);
  vprintf(message, arg_list);
  va_end(arg_list);
  printf("\n");
  pthread_mutex_unlock(&mutex_print);
}

// Safe print to stderr with mutex lock inside.
void print_error(const char *message, ...) {
  pthread_mutex_lock(&mutex_print);
  fprintf(stderr, "[ERROR] ");
  va_list arg_list;
  va_start(arg_list, message);
  vfprintf(stderr, message, arg_list);
  va_end(arg_list);
  fprintf(stderr, "\n");
  pthread_mutex_unlock(&mutex_print);
}
