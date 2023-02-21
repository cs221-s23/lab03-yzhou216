PROG = lab03
OBJS = lab03.o sha256.o passwords.o
TMP = $(PROG) $(OBJS) dict.txt dict.csv

%.o: %.c
	gcc -c -g -o $@ $<

$(PROG): $(OBJS)
	gcc -g -o $@ $^

clean:
	rm -rf $(TMP)
