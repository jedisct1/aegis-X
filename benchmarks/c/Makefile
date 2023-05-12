all: aegis128l aegis128x2 aegis128x4

CFLAGS := -Ofast -march=native

aegis128l:
	$(CC) aegis128l.c -o aegis128l $(CFLAGS)

aegis128x2:
	$(CC) aegis128x2.c -o aegis128x2 $(CFLAGS)

aegis128x4:
	$(CC) aegis128x4.c -o aegis128x4 $(CFLAGS)

clean:
	rm -f aegis128l aegis128x2 aegis128x4