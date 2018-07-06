OBJ=main.o sup_packet.o  pat_print.o sup_session.o
GOBJ=main.c sup_packet.c  pat_print.c sup_session.c
LIB=-lpcap -lm -lz
main:${OBJ}
	gcc -w -o main ${OBJ}  ${LIB}
clean:
	rm -f *.o main core.*
gdb:
	gcc -g -o main ${GOBJ} ${LIB}
