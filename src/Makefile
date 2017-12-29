analyzer : main.o datalinkLayer.o networkLayer.o transportLayer.o applicationLayer.o helper.o
	gcc main.o datalinkLayer.o networkLayer.o transportLayer.o applicationLayer.o helper.o -o analyzer -Wall -Wextra -Werror -lpcap -g

main.o : main.c
	gcc -c main.c -o main.o -g

datalinkLayer.o : datalinkLayer.c datalinkLayer.h
	gcc -c datalinkLayer.c -o datalinkLayer.o -g

networkLayer.o : networkLayer.c networkLayer.h
	gcc -c networkLayer.c -o networkLayer.o -g

transportLayer.o : transportLayer.c transportLayer.h
	gcc -c transportLayer.c -o transportLayer.o -g

applicationLayer.o : applicationLayer.c applicationLayer.h
	gcc -c applicationLayer.c -o applicationLayer.o -g

helper.o : helper.c helper.h
	gcc -c helper.c -o helper.o -g

clean:
	rm -rf *.o
    rm analyzer