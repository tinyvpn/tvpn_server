CC = g++
CFLAGS=
TARGET = tvpn_server
SRCS := $(wildcard *.cpp) 
OBJS := $(patsubst %cpp, %o, $(SRCS)) 

all: $(TARGET) 

$(TARGET): $(OBJS) 
	$(CC) $(CFLAGS) -o $@ $^ -L/root/mbedtls-2.16.6/library -lpthread -lrt -lz -lm -lssl -lcrypto -lmbedtls -lmbedx509 -lmbedcrypto

%.o:%.cpp
	$(CC) $(CFLAGS) -std=c++11 -DLINUX_PLATFORM -I/root/mbedtls-2.16.6/include -c $<

clean: 
	rm -f *.o $(TARGET)
