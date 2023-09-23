all: build
build: client.cpp
	g++ -Ilib client.cpp -o client -std=c++11
clean:
	rm -rf client 
