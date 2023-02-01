
LIBFDT := ../dtc/libfdt
IFLAGS := -I$(LIBFDT)
LDFLAGS	:= -lcrypto++

all:	fix-dtb-smartio

clean:
	rm -f fix-dtb-smartio
	rm -f *.o

fdt.o:	$(LIBFDT)/fdt.c
	gcc -o $@ -Wall $(IFLAGS) -c $<

%.o:	%.cpp
	g++ -o $@ -Wall $(IFLAGS) -c $<


fix-dtb-smartio: FixDtbSmartio.o fdt.o
	g++ -o $@ $^ $(LDFLAGS)
