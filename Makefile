analyzer : main.o ethernet.o ip.o arp.o
	gcc main.o ethernet.o ip.o arp.o -o analyzer -Wall -Wextra -Werror -lpcap -g

main.o : main.c ethernet.h
	gcc -c main.c -o main.o

ethernet.o : ethernet.c ethernet.h ip.h arp.h
	gcc -c ethernet.c -o ethernet.o

ip.o : ip.c ip.h
	gcc -c ip.c -o ip.o

arp.o : arp.c arp.h
	gcc -c arp.c -o arp.o

clean:
	rm -rf *.o