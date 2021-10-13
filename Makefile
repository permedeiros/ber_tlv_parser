# -*- MakeFile -*-
.PHONY: all
all: main

main: main.o libbertlv.so

main.o: main.c ber_tlv.h
	gcc -c main.c -o main.o

libbertlv.so: ber_tlv.c ber_tlv.h
	gcc -o libbertlv.so -fpic -shared ber_tlv.c

.PHONY: clean
clean:
	rm -f *.o *.so main libbertlv.so