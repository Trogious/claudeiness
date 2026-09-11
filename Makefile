CC = clang
CFLAGS = -Wall -Wextra -O2 -arch arm64
LDFLAGS = -lproc
SRC = Sources/claudeiness.c
BIN = claudeiness

.PHONY: all clean install test

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(BIN)

install: $(BIN)
	cp $(BIN) /usr/local/bin/$(BIN)

test: $(BIN)
	python3 Tests/test_cli.py
