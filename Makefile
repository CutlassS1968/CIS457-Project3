everything = server client
all: $(everything)

client: client.c cryptotest.c
	clang -Wall -g -lssl -lcrypto -o $@ $^

server: server.c signal_handler.c cryptotest.c
	clang -Wall -g -lssl -lcrypto -o $@ $^

keys:
	openssl genpkey -algorithm RSA -out RSApriv.pem -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in RSApriv.pem -out RSApub.pem

test: cryptotest.c
	clang -DTEST -g -lssl -lcrypto -o $@ $^

clean:
	 rm $(everything) test
