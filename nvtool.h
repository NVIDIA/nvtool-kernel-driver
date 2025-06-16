/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is part of NVIDIA NVTool kernel driver.
 *
 * Copyright (c) 2024-2025, NVIDIA CORPORATION.  All rights reserved.
 *
 * NVIDIA NVTool kernel driver is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * NVIDIA NVTool kernel driver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NVIDIA NVTool kernel driver.
 * If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _NVTOOL_H_
#define _NVTOOL_H_

#define APERTURE_DEV                "/dev/nvtool"
#define NVTOOL_DEV                  APERTURE_DEV
#define NVTOOL_DEVICE_NAME          "nvtool"

// driver version
#define NVTOOL_VERSION_MAJOR        1
#define NVTOOL_VERSION_MINOR        0
#define NVTOOL_VERSION_PATCH        2

typedef char                        int8;
typedef unsigned char               uint8;
typedef short                       int16;
typedef unsigned short              uint16;
typedef int                         int32;
typedef unsigned int                uint32;
typedef long                        int64;
typedef unsigned long               uint64;
typedef uint8                       Bool;

#define TRUE                        1
#define FALSE                       0

#pragma pack(push)  /// Push current alignment to stack
#pragma pack(1)     /// Set alignment to 1 byte boundary

typedef struct
{
    uint32          index;                  // Index
    uint32          segment;                // PCI segment number
    uint32          bus;                    // PCI bus number
    uint32          device;                 // PCI device number
    uint32          function;               // PCI function number
    uint32          vendorId;               // PCI vendor ID
    uint32          deviceId;               // PCI device ID
    uint64          bar0Addr;               // BAR0 address
    uint32          bar0Size;               // BAR0 size
    uint64          bar0VirtualAddress;     // Map BAR0 physical address bar0_addr into our virtual address space
    struct pci_dev  *pPciDev;               // PCI device info
    void            *pNext;                 // Pointer to next display adapter
} DisplayAdapter;

typedef struct
{
    uint32          segment;
    uint32          bus;
    uint32          device;
    uint32          function;
} PciInfo;

#define NVTOOL_READ_PRIV_REGISTERS_COUNTS_MAX    128
struct NVTOOL_READ_PRIV_REGISTERS
{
    // IN
    PciInfo     pciInfo;
    uint32      offset;
    uint32      count;

    // OUT
    uint32      data[NVTOOL_READ_PRIV_REGISTERS_COUNTS_MAX];
};

struct NVTOOL_READ_PRIV_REGISTER
{
    // IN
    PciInfo     pciInfo;
    uint32      offset;
    uint32      size;

    // OUT
    uint32      value;
};

struct NVTOOL_WRITE_PRIV_REGISTER
{
    // IN
    PciInfo     pciInfo;
    uint32      offset;
    uint32      size;
    uint32      value;
};

#define PCI_CFG_SPACE_LEGACY_MAX                     0x100
#define PCI_CFG_SPACE_EXTENDED_MAX                   0x1000
struct NVTOOL_READ_PCICFG_REGISTER
{
    // IN
    PciInfo     pciInfo;
    uint32      offset;
    uint32      size;

    // OUT
    uint32      value;
};

struct NVTOOL_WRITE_PCICFG_REGISTER
{
    // IN
    PciInfo     pciInfo;
    uint32      offset;
    uint32      value;
    uint32      size;
};

struct NVTOOL_DRIVER_VERSION
{
    // OUT
    uint8       patch;
    uint16      minor;
    uint8       major;
};

struct NVTOOL_DEVICE_INFORMATION
{
    // OUT
    uint32      index;                  // Index
    uint32      segment;                // PCI segment number
    uint32      bus;                    // PCI bus number
    uint32      device;                 // PCI device number
    uint32      function;               // PCI function number
    uint16      vendorId;               // PCI vendor ID
    uint16      deviceId;               // PCI device ID
    uint32      bar0Size;               // BAR0 size
    uint64      bar0Addr;               // BAR0 address
};

struct NVTOOL_DEVICE_COUNT
{
    // OUT
    uint32      counts;
};

#pragma pack(pop)   /// Restore original alignment from stack


#define NVTOOL_IOC_MAGIC                           'n'
#define NVTOOL_IOC_MAX_NUMBER                      11
#define NVTOOL_IOC_BUF_SIZE_MAX                    2048

#define NVTOOLIO(dir, num, type)                   _IO##dir(NVTOOL_IOC_MAGIC, num, struct type)
#define IOCTL_NVTOOL_READ_PRIV_REGISTERS           NVTOOLIO(WR, 1, NVTOOL_READ_PRIV_REGISTERS)
#define IOCTL_NVTOOL_READ_PRIV_REGISTER            NVTOOLIO(WR, 2, NVTOOL_READ_PRIV_REGISTER)
#define IOCTL_NVTOOL_WRITE_PRIV_REGISTER           NVTOOLIO(WR, 3, NVTOOL_WRITE_PRIV_REGISTER)
#define IOCTL_NVTOOL_READ_PCICFG_REGISTER          NVTOOLIO(WR, 4, NVTOOL_READ_PCICFG_REGISTER)
#define IOCTL_NVTOOL_WRITE_PCICFG_REGISTER         NVTOOLIO(WR, 5, NVTOOL_WRITE_PCICFG_REGISTER)
#define IOCTL_NVTOOL_GET_DRIVER_VERSION            NVTOOLIO(WR, 8, NVTOOL_DRIVER_VERSION)

#define NVTOOL_MAX_DEVICES                         56       // NVTOOL_MAX_DEVICES = NVTOOL_IOC_BUF_SIZE_MAX/sizeof(NVTOOL_DEVICE_INFORMATION)
#define IOCTL_NVTOOL_GET_DEVICES                   NVTOOLIO(WR, 9, NVTOOL_DEVICE_INFORMATION[NVTOOL_MAX_DEVICES])
#define IOCTL_NVTOOL_GET_DEVICE_COUNT              NVTOOLIO(WR, 10, NVTOOL_DEVICE_COUNT)

#endif  // _nvtool_H_
