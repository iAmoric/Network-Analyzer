analyzer : main.o datalinkLayer.o networkLayer.o transportLayer.o applicationLayer.o
	gcc main.o datalinkLayer.o networkLayer.o transportLayer.o applicationLayer.o -o analyzer -Wall -Wextra -Werror -lpcap -g

main.o : main.c
	gcc -c main.c -o main.o

datalinkLayer.o : datalinkLayer.c datalinkLayer.h
	gcc -c datalinkLayer.c -o datalinkLayer.o

networkLayer.o : networkLayer.c networkLayer.h
	gcc -c networkLayer.c -o networkLayer.o

transportLayer.o : transportLayer.c transportLayer.h
	gcc -c transportLayer.c -o transportLayer.o

applicationLayer.o : applicationLayer.c applicationLayer.h
	gcc -c applicationLayer.c -o applicationLayer.o

clean:
	rm -rf *.o
