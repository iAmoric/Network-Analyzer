analyzer : main.o ethernet.o ip.o arp.o tcp.o udp.o http.o
	gcc main.o ethernet.o ip.o arp.o tcp.o udp.o http.o -o analyzer -Wall -Wextra -Werror -lpcap -g

main.o : main.c ethernet.h
	gcc -c main.c -o main.o

ethernet.o : ethernet.c ethernet.h ip.h arp.h
	gcc -c ethernet.c -o ethernet.o

ip.o : ip.c ip.h
	gcc -c ip.c -o ip.o

arp.o : arp.c arp.h
	gcc -c arp.c -o arp.o

tcp.o : tcp.c tcp.h
	gcc -c tcp.c -o tcp.o

udp.o : udp.c udp.h
	gcc -c udp.c -o udp.o

http.o : http.c http.h
	gcc -c http.c -o http.o

clean:
	rm -rf *.o
