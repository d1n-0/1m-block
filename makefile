LDLIBS=-lnetfilter_queue

all: 1m-block

1m-block: main.o util.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

1m-block.o: main.cpp

util.o: iphdr.h tcphdr.h util.h util.cpp

clean:
	rm -f 1m-block *.o