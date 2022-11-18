everything = server client
all: $(everything)

client: client.c
	clang -Wall -g -o $@ $^

server: server.c signal_handler.c
	clang -Wall -g -o $@ $^

clean:
	 rm $(everything)
