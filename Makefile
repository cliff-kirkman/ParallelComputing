all:
	cd serial_bruteforce && $(MAKE)
	cd openMP_bruteforce && $(MAKE)
	cd MPI_bruteforce && $(MAKE)

clean:
	cd serial_bruteforce && rm *.o serial_bruteforce
	cd openMP_bruteforce && rm *.o openMP_bruteforce
	cd MPI_bruteforce && rm *.o MPI_bruteforce