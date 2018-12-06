
MPI_bruteforce: main.o 
	mpic++ main.cpp -o MPI_bruteforce -lmpi -lcrypto

main.o: main.cpp
	mpic++ -c main.cpp

clean:
	rm *.o MPI_bruteforce
