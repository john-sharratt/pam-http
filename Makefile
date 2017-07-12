CFLAGS += -Werror -Wall
all: pam-http.so

clean:
	$(RM) test pam-http.so *.o

pam-http.so: src/pam-http.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl
