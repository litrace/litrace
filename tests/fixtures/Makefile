BIN_DIR := bin
FIXTURE_SRCS := $(sort $(wildcard *.c))
FIXTURE_BINS := $(patsubst %.c,$(BIN_DIR)/%,$(FIXTURE_SRCS))

.PHONY: all clean

all: $(FIXTURE_BINS)

$(BIN_DIR)/:
	mkdir -p $@

$(BIN_DIR)/%: %.c | $(BIN_DIR)/
	$(LINK.c) $< -o $@

clean:
	rm -rf $(BIN_DIR)
