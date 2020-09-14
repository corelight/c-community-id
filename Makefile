CC = gcc
SOURCES = example.c
EXECUTABLE = example

CFLAGS = -W -Wall -Wextra `pkg-config --cflags glib-2.0 libgcrypt`
LDFLAGS = `pkg-config --libs glib-2.0 libgcrypt`

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	$(CC) $(SOURCES) $(CFLAGS) $(LDFLAGS) -o $@ 

clean:
	rm -f *.o $(EXECUTABLE)
