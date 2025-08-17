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
#define MAX_DELAY 5

pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_files_json = PTHREAD_MUTEX_INITIALIZER;

static inline cJSON *load_json_file(const char *path);
static inline int save_json_file(const char *path, cJSON *json);

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
