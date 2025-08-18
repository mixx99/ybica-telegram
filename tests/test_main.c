#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int test_serialization();

int main() {
  srand(time(NULL));
  int failed = 0;
  int success = 0;
  if (test_serialization() < 0) {
    fprintf(stderr, "Serialization failed\n");
    failed++;
  } else {
    success++;
  }
  fprintf(stderr, "%d - Success\n%d - Failed\n", success, failed);
}
