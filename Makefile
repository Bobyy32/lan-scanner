
main:
	gcc -g -O0 -Wall -DDEBUG=1 src/*.c src/protocols/*.c -o build/main.out -lpcap -lnet

mdns-test:
	gcc -g -O0 -Wall -DDEBUG=1 src/hashtable.c src/device.c src/capture.c src/protocols/mdns.c tests/mdns_test.c -o build/mdns_test.out -lpcap -lnet

three_prot_test:
	gcc -g -O0 -Wall -DDEBUG=1 src/hashtable.c src/device.c src/capture.c src/protocols/mdns.c src/protocols/arp.c src/protocols/ssdp.c tests/three_prot_test.c -o build/three_prot_test.out -lpcap -lnet

thread_test:
	gcc -g -O0 -Wall -DDEBUG=1 -I src src/hashtable.c src/device.c src/port_scan.c src/capture.c src/scan.c src/protocols/mdns.c src/protocols/arp.c src/protocols/ssdp.c tests/thread_test.c -o build/thread_test.out -lpcap -lnet -lpthread

parse_services_test:
	gcc -g -O0 -Wall -DDEBUG=1 -I src src/hashtable.c src/port_scan.c src/device.c tests/parse_services_test.c -o build/parse_services_test.out -lnet -lpcap

port_scan_test:
	gcc -g -O0 -Wall -DDEBUG=1 src/hashtable.c src/capture.c src/device.c src/scan.c src/port_scan.c src/queue.c src/thread_pool.c src/protocols/arp.c src/protocols/mdns.c src/protocols/ssdp.c tests/port_scan_test.c -o build/port_scan_test.out -lnet -lpcap -lpthread

queue_test:
	gcc -g -Wall -DDEBUG=1 src/queue.c tests/queue_test.c -o build/queue_test.out

thread_pool_test:
	gcc -g -O0 -Wall -DDEBUG=1 src/queue.c src/thread_pool.c tests/thread_pool_test.c -o build/thread_pool_test.out -lpthread

commands_test:
	gcc -g -Wall -DDEBUG=1 tests/commands_test.c -o build/commands_test.out

clean:
	rm -f build/*

run:
	sudo ./build/main.out