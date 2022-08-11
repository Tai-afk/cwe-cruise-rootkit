CR_C := arm-linux-gnueabi-
MODULES := ./linux
obj-m := dolos.o

all:
	        make ARCH=arm CROSS_COMPILE=$(CR_C) -C $(MODULES) M=$(shell pwd) modules

clean:
	        make ARCH=arm CROSS_COMPILE=$(CR_C) -C $(MODULES) M=$(shell pwd) clean
