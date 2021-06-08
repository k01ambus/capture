all:
	sudo apt-get install libpcap-dev
	gcc -o capture input.c sqlite3.c -lpthread -ldl -lm -lpcap

