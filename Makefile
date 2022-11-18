everything = server client
all: $(everything)

client: client.c
	clang -Wall -g -lssl -lcrypto -o $@ $^

server: server.c
	clang -Wall -g -o $@ $^

clean:
	 rm $(everything)
