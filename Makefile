CC = clang
CFLAGS = -Wall -Wextra -O2 -arch arm64
LDFLAGS = -lproc
SRC = Sources/claudeiness.c
BIN = claudeiness

.PHONY: all clean install

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(BIN)

install: $(BIN)
	cp $(BIN) /usr/local/bin/$(BIN)
