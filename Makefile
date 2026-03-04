
main:
	gcc -g -Wall -DDEBUG=1 src/*.c src/protocols/*.c -o build/main.out -lpcap -lnet

mdns-test:
	gcc -g -Wall -DDEBUG=1 src/hashtable.c src/device.c src/capture.c src/protocols/mdns.c tests/mdns_test.c -o build/mdns_test.out -lpcap -lnet

three_prot_test:
	gcc -g -Wall -DDEBUG=1 src/hashtable.c src/device.c src/capture.c src/protocols/mdns.c src/protocols/arp.c src/protocols/ssdp.c tests/three_prot_test.c -o build/three_prot_test.out -lpcap -lnet

clean:
	rm -f build/*

run:
	sudo ./build/main.out