#include "user.h"

#include <pthread.h>
#include <stdlib.h>
#include <time.h>

void *user_input(void *arg) {
  listen_user((User *)arg);
  return NULL;
}

void *user_listen(void *arg) {
  listen_other_users((User *)arg);
  return NULL;
}

int main() {
  srand(time(NULL));

  pthread_t worker_input, worker_listen;
  User user;
  init_user(&user);

  pthread_create(&worker_input, NULL, user_input, &user);
  pthread_create(&worker_listen, NULL, user_listen, &user);

  pthread_join(worker_input, NULL);
  pthread_join(worker_listen, NULL);
}
