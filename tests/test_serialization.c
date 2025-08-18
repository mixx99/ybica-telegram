#include "../source/serialization.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUMBER_OF_TESTS 100

static inline void rand_str(char *dest, size_t length);

int test_serialization() {
  int success = 1;
  Message before_message;
  Message after_message;

  for (int i = 0; i < NUMBER_OF_TESTS; ++i) {
    before_message.context_value = rand();
    before_message.sender_uuid = rand();
    before_message.time = rand();
    before_message.type = rand();
    rand_str(before_message.text, MESSAGE_TEXT_LENGTH);
    rand_str(before_message.sender_name, USER_NAME_SIZE);

    unsigned char buffer[sizeof(before_message)];
    serialize_message(&before_message, buffer);
    deserialize_message(&after_message, buffer);
    if (before_message.context_value != after_message.context_value) {
      fprintf(stderr, "context_value: before %d after %d\n",
              before_message.context_value, after_message.context_value);
      return -1;
    }
    if (before_message.sender_uuid != after_message.sender_uuid) {
      fprintf(stderr, "sender_uuid: before %d after %d\n",
              before_message.sender_uuid, after_message.sender_uuid);
      return -1;
    }
    if (before_message.time != after_message.time) {
      fprintf(stderr, "time: before %d after %d\n", before_message.time,
              after_message.time);
      return -1;
    }
    if (before_message.type != after_message.type) {
      fprintf(stderr, "type: before %d after %d\n", before_message.type,
              after_message.type);
      return -1;
    }
    if (strncmp(before_message.text, after_message.text, MESSAGE_TEXT_LENGTH) !=
        0) {
      fprintf(stderr, "text: before %s after %s\n", before_message.text,
              after_message.text);
      return -1;
    }
    if (strncmp(before_message.sender_name, after_message.sender_name,
                USER_NAME_SIZE) != 0) {
      fprintf(stderr, "name: before %s after %s\n", before_message.sender_name,
              after_message.sender_name);
      return -1;
    }
  }
  return success;
}

void rand_str(char *dest, size_t length) {
  char charset[] = "0123456789"
                   "abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  while (length-- > 1) {
    size_t index = (double)rand() / RAND_MAX * (sizeof charset - 1);
    *dest++ = charset[index];
  }
  *dest = '\0';
}
