#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>

pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;

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
