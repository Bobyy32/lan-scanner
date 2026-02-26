
main:
	gcc -g -Wall src/*.c src/protocols/*.c -o build/main.out -lpcap -lnet

mdns-test:
	gcc -g -Wall src/hashtable.c src/device.c src/capture.c src/protocols/mdns.c tests/mdns_test.c -o build/mdns_test.out -lpcap -lnet

clean:
	rm -f build/*

run:
	sudo ./build/main.out