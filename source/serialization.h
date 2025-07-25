#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "message.h"

unsigned char *serialize_message(Message *message, unsigned char *buffer);
void deserialize_message(Message *message, unsigned char *buffer);

#endif // SERIALIZATION_H
