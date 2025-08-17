#include "serialization.h"
#include "message.h"
#include "user.h"

#include <stdint.h>
#include <string.h>

static inline unsigned char *serialize_int(unsigned char *buffer,
                                           uint32_t value) {
  /* Write big-endian int value into buffer; assumes 32-bit int and 8-bit char.
   */
  buffer[0] = value >> 24;
  buffer[1] = value >> 16;
  buffer[2] = value >> 8;
  buffer[3] = value;
  return buffer + 4;
}

static inline unsigned char *deserialize_int(unsigned char *buffer,
                                             uint32_t *result) {
  *result = 0;
  *result |= (uint32_t)buffer[0] << 24;
  *result |= (uint32_t)buffer[1] << 16;
  *result |= (uint32_t)buffer[2] << 8;
  *result |= (uint32_t)buffer[3];
  return buffer + 4;
}

static inline unsigned char *
deserialize_str(unsigned char *buffer, char *result, uint32_t size_of_str) {
  memcpy(result, buffer, size_of_str);
  return buffer + size_of_str;
}

static inline unsigned char *serialize_str(unsigned char *buffer, char *str,
                                           uint32_t size_of_str) {
  memcpy(buffer, str, size_of_str);
  return buffer + size_of_str;
}

// Serialize a message into buffer. Returns a pointer to end of buffer.
unsigned char *serialize_message(Message *message, unsigned char *buffer) {
  buffer = serialize_int(buffer, message->sender_uuid);
  buffer = serialize_str(buffer, message->sender_name, USER_NAME_SIZE);
  buffer = serialize_int(buffer, message->context_value);
  buffer = serialize_int(buffer, message->type);
  buffer = serialize_int(buffer, message->time);
  buffer = serialize_str(buffer, message->text, MESSAGE_TEXT_LENGTH);
  return buffer;
}

// Deserialize buffer into message.
void deserialize_message(Message *message, unsigned char *buffer) {
  buffer = deserialize_int(buffer, &message->sender_uuid);
  buffer = deserialize_str(buffer, message->sender_name, USER_NAME_SIZE);
  buffer = deserialize_int(buffer, &message->context_value);
  buffer = deserialize_int(buffer, &message->type);
  buffer = deserialize_int(buffer, &message->time);
  buffer = deserialize_str(buffer, message->text, MESSAGE_TEXT_LENGTH);
}
