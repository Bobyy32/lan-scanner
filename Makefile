
all:
	gcc -g -Wall src/main.c src/misc.c src/protocols/*.c -o build/main.out -lpcap -lnet

clean:
	rm -f build/*

run:
	./build/main.out