# PS5 payload SDK build. Set PS5_PAYLOAD_SDK to your installed SDK path.
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
TARGET := slopepk_ps5
SOURCE := ../../source/main.c
CFLAGS := -O2 -Wall -Wextra -std=c11 -DSLOPEPK_PS5
LDFLAGS :=
LIBS :=

.PHONY: all clean
all: $(TARGET).elf

$(TARGET).elf: $(SOURCE)
	@test -x "$(CC)" || { echo "Missing PS5 compiler: $(CC)"; echo "Set PS5_PAYLOAD_SDK to your PS5 Payload SDK folder."; exit 1; }
	$(CC) $(CFLAGS) $(SOURCE) $(LDFLAGS) $(LIBS) -o $@

clean:
	rm -f $(TARGET).elf
