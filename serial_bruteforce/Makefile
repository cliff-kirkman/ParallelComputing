
serial_bruteforce: main.o 
	g++ main.o -o serial_bruteforce -lssl -lcrypto

main.o: main.cpp
	g++ -c main.cpp

clean:
	rm *.o serial_bruteforce