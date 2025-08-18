# make OUT_O_DIR=debug CC=clang CFLAGS="-g -O0"
# make
# make test
# ******
# lcov:
# make coverage
# lcov --capture --directory build --output-file coverage.info
# lcov --remove coverage.info 'thirdparty/*' --output-file coverage.info
# genhtml coverage.info --output-directory coverage-report
# ******
# make clean

ifeq ($(origin CC),default)
  CC = gcc
endif

CFLAGS ?= -O2 -Ithirdparty
LDFLAGS ?= -lssl -lcrypto
OUT_O_DIR ?= build
SRC = ./source
TEST_DIR = ./tests
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CSRC = source/main.c source/message.c source/user.c source/log.c source/serialization.c source/crypto.c source/crc.c thirdparty/cJSON/cJSON.c

TEST_SRC = tests/test_main.c tests/test_serialization.c

# reproducing source tree in object tree
COBJ := $(addprefix $(OUT_O_DIR)/,$(CSRC:.c=.o))
TEST_OBJ = $(addprefix $(OUT_O_DIR)/,$(TEST_SRC:.c=.o))
DEPS = $(COBJ:.o=.d)

.PHONY: all
all: $(OUT_O_DIR)/chat.x

$(OUT_O_DIR)/chat.x: $(COBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

# static pattern rule to not redefine generic one
$(COBJ) : $(OUT_O_DIR)/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(DEPS) : $(OUT_O_DIR)/%.d : %.c
	@mkdir -p $(@D)
	$(CC) -E $(CFLAGS) $< -MM -MT $(@:.d=.o) > $@

.PHONY: test
test: $(OUT_O_DIR)/test.x
	./$(OUT_O_DIR)/test.x

$(OUT_O_DIR)/test.x: $(TEST_OBJ) $(filter-out $(OUT_O_DIR)/source/main.o,$(COBJ))
	@mkdir -p $(@D)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OUT_O_DIR)/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: coverage
coverage: CFLAGS += -O0 -g -fprofile-arcs -ftest-coverage -Ithirdparty
coverage: LDFLAGS += -fprofile-arcs -lssl -lcrypto
coverage: test

.PHONY: clean
clean:
	rm -rf $(COBJ) $(DEPS) $(TEST_OBJ) $(OUT_O_DIR)/*.x $(OUT_O_DIR)/*.log
	find $(OUT_O_DIR) -name '*.gcda' -delete
	find $(OUT_O_DIR) -name '*.gcno' -delete

# targets which we have no need to recollect deps
NODEPS = clean

ifeq (0, $(words $(findstring $(MAKECMDGOALS), $(NODEPS))))
include $(DEPS)
endif
