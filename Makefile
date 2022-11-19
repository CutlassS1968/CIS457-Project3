everything = server client
all: $(everything)

client: client.c
	clang -Wall -g -o $@ $^

server: server.c signal_handler.c
	clang -Wall -g -o $@ $^

keys:
	openssl genpkey -algorithm RSA -out RSApriv.pem -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in RSApriv.pem -out RSApub.pem

test: cryptotest.c
	clang -g -lssl -lcrypto -o $@ $^

clean:
	 rm $(everything) test
