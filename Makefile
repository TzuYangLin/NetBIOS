EXE = nat

all: 	$(EXE)

clean:
	rm -f *.o

msn:	nat.o
	gcc -o $@ $^
