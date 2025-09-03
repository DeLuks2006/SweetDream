# I regret starting this project...
CC = x86_64-w64-mingw32-g++

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -fno-exceptions -fno-rtti -Wl,-Tlink.ld
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

OUTX64	:= SweetDream.x64.exe
BINX64	:= SweetDream.x64.bin

all:
	@ nasm -f win64 asm/Start.asm -o Start.x64.o
	@ nasm -f win64 asm/GetIp.asm -o GetIp.x64.o
	@ $(CC) src/*.cpp Start.x64.o GetIp.x64.o -o $(OUTX64) $(CFLAGS) $(LFLAGS) -I.
	@ python3 python3/extract.py -f $(OUTX64) -o $(BINX64)

clean:
	@ rm -rf *.o
	@ rm -rf *.bin
	@ rm -rf *.exe
