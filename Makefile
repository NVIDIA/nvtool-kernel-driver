# SPDX-License-Identifier: GPL-2.0
#
# This file is part of NVIDIA NVTool kernel driver.
#
# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# NVIDIA NVTool kernel driver is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# NVIDIA NVTool kernel driver is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NVIDIA NVTool kernel driver.
# If not, see <http://www.gnu.org/licenses/>.
#
CONFIG_NVFLASH_SYS=m

DEBUG_NVTOOL ?= true

CROSS_COMPILE ?= 


KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

AS          = $(CROSS_COMPILE)as
LD          = $(CROSS_COMPILE)ld
CC          = $(CROSS_COMPILE)gcc
CPP         = $(CC) -E
AR          = $(CROSS_COMPILE)ar
NM          = $(CROSS_COMPILE)nm
STRIP       = $(CROSS_COMPILE)strip
OBJCOPY     = $(CROSS_COMPILE)objcopy
OBJDUMP     = $(CROSS_COMPILE)objdump

obj-$(CONFIG_NVFLASH_SYS) :=  nvtool.o

PWD := $(shell pwd)

.PHONY : all clean

all:
	make CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) modules
install:
	make CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) modules_install
clean:
	rm *.o *.ko *.symvers *.order
