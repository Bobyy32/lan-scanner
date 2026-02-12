
all:
	gcc -g -Wall src/main.c src/device.c src/capture.c src/protocols/*.c -o build/main.out -lpcap -lnet

clean:
	rm -f build/*

run:
	sudo ./build/main.out