CXX    = g++
CFLAGS = -Wall -Wextra -std=c++20 -O3 -march=native
LIBS   = -pthread -lcurl -lgmpxx -lgmp
HPP    = main.hpp Pool.hpp Pool.hpp tools.hpp

all: CFLAGS += -s
all: StellaPoolM

debug: CFLAGS += -g
debug: StellaPoolM

StellaPoolM: main.o Pool.o tools.o
	$(CXX) $(CFLAGS) -o StellaPoolM $^ $(LIBS)

main.o: main.cpp $(HPP)
	$(CXX) $(CFLAGS) -c -o main.o main.cpp

Pool.o: Pool.cpp $(HPP)
	$(CXX) $(CFLAGS) -c -o Pool.o Pool.cpp

tools.o: tools.cpp $(HPP)
	$(CXX) $(CFLAGS) -c -o tools.o tools.cpp

clean:
	rm -rf StellaPoolM *.o
