# Makefile2.6
ifneq ($(KERNELRELEASE),)
#kbuild syntax. dependency relationshsip of files and target modules are listed here.

mymodule-objs := aqmplus.o
obj-m := aqmplus.o   

else
PWD  := $(shell pwd)

KVER ?= $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
#KDIR目录其实是链接到上面那个Makefile中的那个/usr/src/linux-source-2.6.15/*中
all:
	$(MAKE) -C $(KDIR) M=$(PWD)

client:
	gcc client.c -o client

clean:
	rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions

install:
	cp aqmplus.ko /lib/modules/$(KVER)/kernel/net/sched

endif

