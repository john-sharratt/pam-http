CFLAGS += -Werror -Wall
all: pam_http.so pamtester

clean:
	$(RM) test pam_http.so *.o

pam_http.so: src/pam_http.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl

pamtester: src/pamtester.c
	$(CC) $(CFLAGS) -o $@ $< -lpam -lpam_misc