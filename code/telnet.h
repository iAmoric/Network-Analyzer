#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#define NOP     241     //No Operation
#define DM      242     //Data Mark
#define IP      244     //Interrupt process
#define AO      245     //Abort output--but
#define AYT     246     //Are you there
#define EC      247     //Erase character
#define EL      248     //Erase line
#define GA      249     //Go ahead
#define SB      250     //les donnees qui suivents sont une négociation d'options
#define SE      240     //fin de la négociation d'options
#define WILL    251
#define WONT    252
#define DO      253
#define DONT    254
#define IAC     255     //Interpret as command (caractere d'echappement)

void handle_telnet(const u_char* packet);
