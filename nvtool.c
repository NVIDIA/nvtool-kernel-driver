// SPDX-License-Identifier: GPL-2.0
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
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/version.h>

#include "nvtool.h"

#define DEVICE_NUMBER           1

#ifdef DEBUG_NVTOOL
#define DBG(fmt,args...) printk("[%s]:%d => "fmt,__FUNCTION__,__LINE__,##args)
#else
#define DBG(fmt,args...)
#endif

static DisplayAdapter   *g_pDisplayAdapter = NULL;
static uint32           g_displayAdapterCounts = 0;
static dev_t            g_devno = 0;
static Bool             g_pciDriverRegistered = FALSE;

static int              g_DeviceOpened = 0;
static struct class     *g_pClass = NULL;
static struct cdev      g_nvtool_cdev;

static DEFINE_SPINLOCK( status_lock );

static const struct pci_device_id nvtool_pci_table[] =
{
    {
        .vendor        = PCI_VENDOR_ID_NVIDIA,
        .device        = PCI_ANY_ID,
        .subvendor     = PCI_ANY_ID,
        .subdevice     = PCI_ANY_ID,
        .class         = (PCI_CLASS_DISPLAY_VGA << 8),
        .class_mask    = ~0
    },
    {
        .vendor        = PCI_VENDOR_ID_NVIDIA,
        .device        = PCI_ANY_ID,
        .subvendor     = PCI_ANY_ID,
        .subdevice     = PCI_ANY_ID,
        .class         = (PCI_CLASS_DISPLAY_3D << 8),
        .class_mask    = ~0
    },
    {
        .vendor        = PCI_VENDOR_ID_NVIDIA,
        .device        = PCI_ANY_ID,
        .subvendor     = PCI_ANY_ID,
        .subdevice     = PCI_ANY_ID,
        .class         = (PCI_CLASS_BRIDGE_OTHER << 8),
        .class_mask    = ~0
    },
    { 0 }
};

static int nvtool_pci_probe
(
    struct pci_dev *pdev,
    const struct pci_device_id *id
)
{
    DisplayAdapter *pDisplayAdapter = NULL;
    printk("nvtool: Loaded PCI driver %04x:%02x:%02x.%x vendor %04x device %04x\n",
            pci_domain_nr(pdev->bus),
            pdev->bus->number,
            PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn),
            pdev->vendor,
            pdev->device );

    if ( pci_enable_device(pdev) != 0 )
    {
        pr_err("pci_enable_device failed\n");
        return -1;
    }

    pci_set_master( pdev );
    if ( pci_request_region( pdev, 0, NVTOOL_DEVICE_NAME ) != 0 )
    {
        pr_err("pci_request_region: unable to get BAR0\n");
        return -1;
    }

    if ( pci_resource_start( pdev, 0 ) == 0 )
    {
        pr_err("pci_resource_start BAR0 failed\n");
        return -1;
    }

    if ( pci_resource_len( pdev, 0 ) == 0 )
    {
        pr_err("pci_resource_len: Invalid BAR0 length\n");
        return -1;
    }

    pDisplayAdapter = (DisplayAdapter*)kmalloc( sizeof(DisplayAdapter), GFP_KERNEL );
    if ( !pDisplayAdapter )
    {
        pr_err("ERROR: kmalloc failed for %04x:%02x:%02x.%x\n", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn) );
        return -1;
    }

    memset( pDisplayAdapter, 0, sizeof(DisplayAdapter) );

    pDisplayAdapter->index = g_displayAdapterCounts;
    pDisplayAdapter->segment = pci_domain_nr(pdev->bus);
    pDisplayAdapter->bus = pdev->bus->number;
    pDisplayAdapter->device = PCI_SLOT(pdev->devfn);
    pDisplayAdapter->function = PCI_FUNC(pdev->devfn);
    pDisplayAdapter->vendorId = pdev->vendor;
    pDisplayAdapter->deviceId = pdev->device;
    pDisplayAdapter->bar0Addr = pci_resource_start( pdev, 0 );
    pDisplayAdapter->bar0Size = pci_resource_len( pdev, 0 );
    pDisplayAdapter->bar0VirtualAddress = (uint64)pci_iomap( pdev, 0, pDisplayAdapter->bar0Size );

    pDisplayAdapter->pPciDev = pdev;

    pDisplayAdapter->pNext = NULL;
    if ( g_pDisplayAdapter == NULL )
    {
        g_pDisplayAdapter = pDisplayAdapter;
    }
    else
    {
        DisplayAdapter *pEnumDisplayAdapter;
        for ( pEnumDisplayAdapter = g_pDisplayAdapter; pEnumDisplayAdapter != NULL; pEnumDisplayAdapter = (DisplayAdapter*)pEnumDisplayAdapter->pNext )
        {
            if ( pEnumDisplayAdapter->pNext != NULL )
            {
                continue;
            }

            pEnumDisplayAdapter->pNext = pDisplayAdapter;
            break;
        }
    }

    g_displayAdapterCounts++;

    printk( "nvtool: Number of detected display adapter = %d\n", g_displayAdapterCounts );
    return 0;
}

/*!
 * @brief Cleanup when device is removed
 * This function is automatically called by the kernel PCI code when the
 * registered device is disconnected or when #pci_unregister_driver is called.
 */
static void nvtool_pci_remove
(
    struct pci_dev *pdev
)
{
    DisplayAdapter *pEnumDisplayAdapter = g_pDisplayAdapter;
    DisplayAdapter *pPrevDisplayAdapter = NULL;

    while ( pEnumDisplayAdapter != NULL )
    {
        DisplayAdapter *pNextDisplayAdapter = (DisplayAdapter *)pEnumDisplayAdapter->pNext;
        if ( ( pci_domain_nr(pdev->bus) == pEnumDisplayAdapter->segment ) &&
             ( pdev->bus->number == pEnumDisplayAdapter->bus ) &&
             ( PCI_SLOT(pdev->devfn) == pEnumDisplayAdapter->device ) &&
             ( PCI_FUNC(pdev->devfn) == pEnumDisplayAdapter->function ) &&
             ( pdev->vendor == pEnumDisplayAdapter->vendorId ) &&
             ( pdev->device == pEnumDisplayAdapter->deviceId ) )
        {
            if ( pEnumDisplayAdapter->bar0VirtualAddress != 0 )
            {
                pci_iounmap( pdev, (void __iomem *)pEnumDisplayAdapter->bar0VirtualAddress );
                pEnumDisplayAdapter->bar0VirtualAddress = 0;
            }

            if ( pPrevDisplayAdapter != NULL )
            {
                pPrevDisplayAdapter->pNext = pNextDisplayAdapter;
            }
            else
            {
                g_pDisplayAdapter = pNextDisplayAdapter;
            }

            kfree(pEnumDisplayAdapter);
        }
        else
        {
            pPrevDisplayAdapter = pEnumDisplayAdapter;
        }

        pEnumDisplayAdapter = pNextDisplayAdapter;
    }

    pci_release_region( pdev, 0 );

    pci_disable_device( pdev );

    printk("nvtool: Unloaded PCI driver %04x:%02x:%02x.%x vendor %04x device %04x\n",
            pci_domain_nr(pdev->bus),
            pdev->bus->number,
            PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn),
            pdev->vendor, pdev->device );
}

// PCI ERROR FUNCTIONS and PCI error handler callback table
static pci_ers_result_t nvtool_pci_error_detected
(
    struct pci_dev *pdev,
    pci_channel_state_t state
)
{
    DBG( "pci_error_detected dev %04x:%02x:%02x.%x\n",
            pci_domain_nr(pdev->bus),
            pdev->bus->number,
            PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn) );

    return PCI_ERS_RESULT_CAN_RECOVER;
}

static pci_ers_result_t nvtool_pci_mmio_enabled
(
    struct pci_dev *pdev
)
{
    DBG( "pci_mmio_enabled dev %04x:%02x:%02x.%x\n",
            pci_domain_nr(pdev->bus),
            pdev->bus->number,
            PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn) );

    return PCI_ERS_RESULT_NEED_RESET;
}

static void nvtool_pci_resume
(
    struct pci_dev *pdev
)
{
    DBG( "pci_resume dev %04x:%02x:%02x.%x\n",
            pci_domain_nr(pdev->bus),
            pdev->bus->number,
            PCI_SLOT(pdev->devfn),
            PCI_FUNC(pdev->devfn) );
}

static struct pci_error_handlers nvtool_pci_error_handlers =
{
    .error_detected     = nvtool_pci_error_detected,
    .mmio_enabled       = nvtool_pci_mmio_enabled,
    .resume             = nvtool_pci_resume,
};

// PCI event callbacks
static struct pci_driver nvtool_pci_driver =
{
    .name               = NVTOOL_DEVICE_NAME,
    .id_table           = nvtool_pci_table,
    .probe              = nvtool_pci_probe,
    .remove             = nvtool_pci_remove,
    .err_handler        = &nvtool_pci_error_handlers,
};

/*!
 *  @brief  Get PCI device from supported list
 *  @param  domain      PCI segment number
 *  @param  bus         PCI bus number
 *  @param  device      PCI device number
 *  @param  function    PCI function number
 *  @return Pointer of matched display adapter if found, or null.
 */
DisplayAdapter* GetPciDevice
(
    uint32 segment,
    uint32 bus,
    uint32 device,
    uint32 function
)
{
    DisplayAdapter *pEnumDisplayAdapter = NULL;

    for ( pEnumDisplayAdapter = g_pDisplayAdapter;
          pEnumDisplayAdapter != NULL;
          pEnumDisplayAdapter = (DisplayAdapter *)pEnumDisplayAdapter->pNext )
    {
        DBG("Iterating Display Adapter (%04X,%04X) S:%02X,B:%02X,D:%02X,F:%02X...\n",
                pEnumDisplayAdapter->vendorId,
                pEnumDisplayAdapter->deviceId,
                pEnumDisplayAdapter->segment,
                pEnumDisplayAdapter->bus,
                pEnumDisplayAdapter->device,
                pEnumDisplayAdapter->function );

        if ( ( segment == pEnumDisplayAdapter->segment ) &&
             ( bus == pEnumDisplayAdapter->bus ) &&
             ( device == pEnumDisplayAdapter->device ) &&
             ( function == pEnumDisplayAdapter->function ) )
        {
            return pEnumDisplayAdapter;
        }
    }

    if ( pEnumDisplayAdapter == NULL )
    {
        DBG("No device found with specified S:%02X,B:%02X,D:%02X,F:%02X.\n",
            segment,
            bus,
            device,
            function );
    }

    return NULL;
}

/*!
 *  @brief  Register the PCI driver
 *  @param  none
 *  @return 0 on success or a negative value on failure.
 */
int InitializePciDriver( void )
{
    int ret;
    uint32 index;
    DisplayAdapter *pEnumDisplayAdapter;

    ret = pci_register_driver( &nvtool_pci_driver );
    if ( ret == 0 )
    {
        g_pciDriverRegistered = TRUE;
    }

    for ( pEnumDisplayAdapter = g_pDisplayAdapter, index = 0;
          pEnumDisplayAdapter != NULL;
          pEnumDisplayAdapter = (DisplayAdapter *)pEnumDisplayAdapter->pNext, ++index )
    {
        DBG("<%02d> Device (%04X,%04X) S:%02X,B:%02X,D:%02X,F:%02X,BAR0:0x%08lX,SIZE:%07X,VMA:%08lX\n",
                index,
                pEnumDisplayAdapter->vendorId,
                pEnumDisplayAdapter->deviceId,
                pEnumDisplayAdapter->segment,
                pEnumDisplayAdapter->bus,
                pEnumDisplayAdapter->device,
                pEnumDisplayAdapter->function,
                pEnumDisplayAdapter->bar0Addr,
                pEnumDisplayAdapter->bar0Size,
                pEnumDisplayAdapter->bar0VirtualAddress );
    }

    return ret;
}

/*!
 *  @brief  Unregister the PCI driver
 *  @param  none
 *  @return none
 */
void DeinitializePciDriver( void )
{
    if ( g_pciDriverRegistered )
    {
        pci_unregister_driver( &nvtool_pci_driver );
        g_pciDriverRegistered = FALSE;
    }
}

/*!
 *  @brief  Read amount of priv registers
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_READ_PRIV_REGISTER struct
 *  @return 0 on success or a negative value on failure.
 */
int ReadPrivRegisters
(
    struct file *f,
    struct NVTOOL_READ_PRIV_REGISTERS *p
)
{
    uint32 i;
    uint64 offset;
    uint64 offsetEnd;
    uint64 barEnd;
    unsigned long flags;
    DisplayAdapter *pDisplayAdapter = GetPciDevice( p->pciInfo.segment, p->pciInfo.bus, p->pciInfo.device, p->pciInfo.function );
    if ( pDisplayAdapter == NULL )
    {
        return -ENXIO;
    }

    if ( ( p->count == 0 ) || ( p->count > NVTOOL_READ_PRIV_REGISTERS_COUNTS_MAX ) )
    {
        return -EINVAL;
    }

    if ( pDisplayAdapter->bar0Size < ( NVTOOL_READ_PRIV_REGISTERS_COUNTS_MAX * sizeof(uint32) ) )
    {
        pr_err( "BAR0 size (0x%X) too small for expected register access\n", pDisplayAdapter->bar0Size );
        return -EINVAL;
    }

    offsetEnd = p->offset + p->count * sizeof(uint32);
    barEnd = pDisplayAdapter->bar0VirtualAddress + pDisplayAdapter->bar0Size;
    if ( ( pDisplayAdapter->bar0VirtualAddress + offsetEnd ) >= barEnd )
    {
        pr_err( "Invalid offset: 0x%lX is outside access range 0x%lX\n", ( pDisplayAdapter->bar0VirtualAddress + offsetEnd ), barEnd );
        return -EINVAL;
    }

    spin_lock_irqsave( &status_lock, flags );
    for ( offset = p->offset, i = 0;
          ( offset < offsetEnd ) && ( i < NVTOOL_READ_PRIV_REGISTERS_COUNTS_MAX );
          offset += sizeof(uint32), ++i )
    {
        p->data[i] = ioread32( (void __iomem *)pDisplayAdapter->bar0VirtualAddress + offset );
    }
    spin_unlock_irqrestore( &status_lock, flags );

    return 0;
}

/*!
 *  @brief  Read priv register with with specify data length 1/2/4(default).
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_READ_PRIV_REGISTER struct
 *  @return 0 on success or a negative value on failure.
 */
int ReadPrivRegister
(
    struct file *f,
    struct NVTOOL_READ_PRIV_REGISTER *p
)
{
    uint64 offset;
    uint64 barEnd;
    unsigned long flags;
    DisplayAdapter *pDisplayAdapter = GetPciDevice( p->pciInfo.segment, p->pciInfo.bus, p->pciInfo.device, p->pciInfo.function );
    if ( pDisplayAdapter == NULL )
    {
        return -ENXIO;
    }

    offset = pDisplayAdapter->bar0VirtualAddress + p->offset;
    barEnd = pDisplayAdapter->bar0VirtualAddress + pDisplayAdapter->bar0Size;
    if ( offset >= barEnd )
    {
        pr_err( "Invalid offset: 0x%lX is outside access range 0x%lX\n", offset, barEnd );
        return -EINVAL;
    }

    spin_lock_irqsave( &status_lock, flags );
    switch ( p->size )
    {
        case 1:
        {
            p->value = ioread8( (void __iomem *)offset );
            break;
        }
        case 2:
        {
            p->value = ioread16( (void __iomem *)offset );
            break;
        }
        case 4:
        {
            p->value = ioread32( (void __iomem *)offset );
            break;
        }
        default:
        {
            spin_unlock_irqrestore( &status_lock, flags );
            return -ENOTSUPP;
        }
    }
    spin_unlock_irqrestore( &status_lock, flags );

    return 0;
}

/*!
 *  @brief  write priv register with specify data length 1/2/4(default).
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_WRITE_PRIV_REGISTER struct
 *  @return 0 on success or a negative value on failure.
 */
int WritePrivRegister
(
    struct file *f,
    struct NVTOOL_WRITE_PRIV_REGISTER *p
)
{
    uint64 offset;
    uint64 barEnd;
    unsigned long flags;
    DisplayAdapter *pDisplayAdapter = GetPciDevice( p->pciInfo.segment, p->pciInfo.bus, p->pciInfo.device, p->pciInfo.function );
    if ( pDisplayAdapter == NULL )
    {
        return -ENXIO;
    }

    offset = pDisplayAdapter->bar0VirtualAddress + p->offset;
    barEnd = pDisplayAdapter->bar0VirtualAddress + pDisplayAdapter->bar0Size;
    if ( offset >= barEnd )
    {
        pr_err( "Invalid offset: 0x%lX is outside access range 0x%lX\n", offset, barEnd );
        return -EINVAL;
    }

    spin_lock_irqsave( &status_lock, flags );
    switch ( p->size )
    {
        case 1:
        {
            iowrite8(  p->value, (void __iomem *)offset );
            break;
        }
        case 2:
        {
            iowrite16(  p->value, (void __iomem *)offset );
            break;
        }
        case 4:
        {
            iowrite32(  p->value, (void __iomem *)offset );
            break;
        }
        default:
        {
            spin_unlock_irqrestore( &status_lock, flags );
            return -ENOTSUPP;
        }
    }
    spin_unlock_irqrestore( &status_lock, flags );

    return 0;
}

/*!
 *  @brief  Read PCI CFG register with length DWORD
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_READ_PCICFG_REGISTER struct
 *  @return 0 on success or a negative value on failure.
 */
int ReadPciCfgRegister
(
    struct file *f,
    struct NVTOOL_READ_PCICFG_REGISTER *p
)
{
    uint32 maxCfg;
    unsigned long flags;
    DisplayAdapter *pDisplayAdapter = GetPciDevice( p->pciInfo.segment, p->pciInfo.bus, p->pciInfo.device, p->pciInfo.function );
    if ( pDisplayAdapter == NULL )
    {
        return -ENXIO;
    }

    maxCfg = pci_is_pcie( pDisplayAdapter->pPciDev ) ? PCI_CFG_SPACE_EXTENDED_MAX : PCI_CFG_SPACE_LEGACY_MAX;
    if ( ( p->offset >= maxCfg ) ||
         ( p->offset + p->size ) > maxCfg )
    {
        pr_err( "Illegal config access: offset=0x%X size=%u\n", p->offset, p->size );
        return -EINVAL;
    }

    spin_lock_irqsave( &status_lock, flags );
    switch ( p->size )
    {
        case 1:
        {
            pci_read_config_byte( pDisplayAdapter->pPciDev, p->offset, (uint8*)&p->value );
            break;
        }
        case 2:
        {
            pci_read_config_word( pDisplayAdapter->pPciDev, p->offset, (uint16*)&p->value );
            break;
        }
        case 4:
        {
            pci_read_config_dword( pDisplayAdapter->pPciDev, p->offset, &p->value );
            break;
        }
        default:
        {
            spin_unlock_irqrestore( &status_lock, flags );
            return -ENOTSUPP;
        }
    }

    spin_unlock_irqrestore( &status_lock, flags );
    return 0;
}

/*!
 *  @brief  Write PCI CFG register with length DWORD
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_WRITE_PCICFG_REGISTER struct
 *  @return 0 on success or a negative value on failure.
 */
int WritePciCfgRegister
(
    struct file *f,
    struct NVTOOL_WRITE_PCICFG_REGISTER *p
)
{
    uint32 maxCfg;
    unsigned long flags;
    DisplayAdapter *pDisplayAdapter = GetPciDevice( p->pciInfo.segment, p->pciInfo.bus, p->pciInfo.device, p->pciInfo.function );
    if ( pDisplayAdapter == NULL )
    {
        return -ENXIO;
    }

    maxCfg = pci_is_pcie( pDisplayAdapter->pPciDev ) ? PCI_CFG_SPACE_EXTENDED_MAX : PCI_CFG_SPACE_LEGACY_MAX;
    if ( ( p->offset >= maxCfg ) ||
         ( p->offset + p->size ) > maxCfg )
    {
        pr_err( "Illegal config access: offset=0x%X size=%u\n", p->offset, p->size );
        return -EINVAL;
    }

    spin_lock_irqsave( &status_lock, flags );
    switch ( p->size )
    {
        case 1:
        {
            if ( p->value > 0xFFU )
            {
                pr_err( "Invalid byte data 0x%x for PCI CFG write.\n", p->value );
                spin_unlock_irqrestore( &status_lock, flags );
                return -EINVAL;
            }
            pci_write_config_byte( pDisplayAdapter->pPciDev, p->offset, (uint8)p->value );
            break;
        }
        case 2:
        {
            if ( p->value > 0xFFFFU )
            {
                pr_err( "Invalid word data 0x%x for PCI CFG write.\n", p->value );
                spin_unlock_irqrestore( &status_lock, flags );
                return -EINVAL;
            }
            pci_write_config_word( pDisplayAdapter->pPciDev, p->offset, (uint16)p->value );
            break;
        }
        case 4:
        {
            pci_write_config_dword( pDisplayAdapter->pPciDev, p->offset, p->value );
            break;
        }
        default:
        {
            spin_unlock_irqrestore( &status_lock, flags );
            return -ENOTSUPP;
        }
    }
    spin_unlock_irqrestore( &status_lock, flags );

    return 0;
}

/*!
 *  @brief  Get nvtool driver version
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_DRIVER_VERSION struct
 *  @return 0 on success or a negative value on failure.
 */
int GetDriverVersion
(
    struct file *f,
    struct NVTOOL_DRIVER_VERSION *p
)
{
    p->major = NVTOOL_VERSION_MAJOR;
    p->minor = NVTOOL_VERSION_MINOR;
    p->patch = NVTOOL_VERSION_PATCH;

    return 0;
}

/*!
 *  @brief  Get the enumerated devices
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_DEVICE_INFORMATION struct
 *  @return 0 on success or a negative value on failure.
 */
int GetDevices
(
    struct file *f,
    struct NVTOOL_DEVICE_INFORMATION *p
)
{
    DisplayAdapter *pEnumDisplayAdapter = NULL;

    for ( pEnumDisplayAdapter = g_pDisplayAdapter;
          pEnumDisplayAdapter != NULL;
          pEnumDisplayAdapter = (DisplayAdapter *)pEnumDisplayAdapter->pNext, p++ )
    {
        p->index                = (uint8)pEnumDisplayAdapter->index;
        p->segment              = (uint16)pEnumDisplayAdapter->segment;
        p->bus                  = (uint8)pEnumDisplayAdapter->bus;
        p->device               = (uint8)pEnumDisplayAdapter->device;
        p->function             = (uint8)pEnumDisplayAdapter->function;
        p->vendorId             = (uint16)pEnumDisplayAdapter->vendorId;
        p->deviceId             = (uint16)pEnumDisplayAdapter->deviceId;
        p->bar0Addr             = pEnumDisplayAdapter->bar0Addr;
        p->bar0Size             = (uint32)pEnumDisplayAdapter->bar0Size;
    }

    return 0;
}

/*!
 *  @brief  Get count of devices
 *  @param  f  file structure
 *  @param  p  pointer of NVTOOL_DEVICE_COUNT struct
 *  @return 0 on success or a negative value on failure.
 */
int GetDeviceCount
(
    struct file *f,
    struct NVTOOL_DEVICE_COUNT *p
)
{
    p->counts = g_displayAdapterCounts;

    return 0;
}

static ssize_t nvtool_read
(
    struct file *filep,
    char *buffer,
    size_t len,
    loff_t *offset
)
{
    pr_err(KERN_ERR "NVTOOL Read CMD: This operation isn't supported.\n");
    return (-EINVAL);
}


static ssize_t nvtool_write
(
    struct file *filp,
    const char *buf,
    size_t len,
    loff_t *f_ops
)
{
    pr_err(KERN_ERR "NVTOOL Write CMD: This operation isn't supported.\n");
    return (-EINVAL);
}


static long nvtool_ioctl
(
    struct file *f,
    unsigned int cmd,
    unsigned long arg
)
{
    int ret = 0;
    uint8 buffer[NVTOOL_IOC_BUF_SIZE_MAX] = {0};
    int argSize = _IOC_SIZE( cmd );

    if ( argSize > (int)sizeof(buffer) )
    {
        // TODO: Allocate more buffer for arguments
        pr_err( KERN_ERR "cmd %d : Buffer not enough for copying ioctl data ( size %X ).\n", cmd, argSize );
        return -ENOMEM;
    }

    if ( argSize > 0 )
    {
        if ( copy_from_user( &buffer, (void __user *)arg, argSize ) )
        {
            pr_err( KERN_ERR "cmd %d : Failed to copy ioctl data.\n", cmd );
            return -EFAULT;
        }
    }

#define NVTOOL_IOCTL_ARGS(code, function, argtype, argtypeAmount ) \
    ( { \
        do \
        { \
            DBG("ioctl(" #code ")\n");\
            if ( argSize != ( sizeof( struct argtype ) * argtypeAmount ) ) \
            { \
                ret = -EINVAL;\
                DBG("Invalid parameter passed to ioctl " #code ".\n"); \
            } \
            else\
            { \
                ret = function( f, (struct argtype *)buffer); \
                if ( ( ret == 0 ) && \
                     copy_to_user( (void __user *)arg, buffer, argSize ) ) \
                { \
                    ret = -EFAULT;\
                    DBG("Copying return value for ioctl" #code " to user space failed.\n"); \
                } \
            } \
        } while (0);\
     } )

#define NVTOOL_IOCTL(code, function, argtype) \
    ( { \
        do \
        { \
            DBG("ioctl(" #code ")\n");\
            if ( argSize != sizeof( struct argtype ) ) \
            { \
                ret = -EINVAL;\
                DBG("Invalid parameter passed to ioctl " #code ".\n"); \
            } \
            else\
            { \
                ret = function( f, (struct argtype *)buffer); \
                if ( ( ret == 0 ) && \
                     copy_to_user( (void __user *)arg, buffer, argSize ) ) \
                { \
                    ret = -EFAULT;\
                    DBG("Copying return value for ioctl" #code " to user space failed.\n"); \
                } \
            } \
        } while (0);\
     } )

#define NVTOOL_IOCTL_NORETVAL(code, function, argtype) \
    ( { \
        do \
        { \
            DBG("ioctl(" #code ")\n"); \
            if ( argSize != sizeof( struct argtype ) ) \
            { \
                ret = -EINVAL; \
                DBG("Invalid parameter passed to ioctl " #code "\n"); \
            } \
            else \
            { \
                ret = function( f, (struct argtype *)buffer); \
            } \
        } while (0); \
     } )

#define NVTOOL_IOCTL_VOID(code, function) \
    ( { \
        do \
        { \
            DBG( "ioctl(" #code ")\n"); \
            if ( argSize != 0 ) \
            { \
                ret = -EINVAL;\
                DBG("Invalid parameter passed to ioctl " #code "\n"); \
            } \
            else \
            { \
                ret = function(f); \
            } \
        } while (0);\
      } )

    if ( ( _IOC_TYPE(cmd) != NVTOOL_IOC_MAGIC ) ||
         ( _IOC_NR(cmd) > NVTOOL_IOC_MAX_NUMBER ) )
    {
        return -ENOTTY;
    }

    switch( cmd )
    {
        case IOCTL_NVTOOL_READ_PRIV_REGISTERS:
        {
            NVTOOL_IOCTL(
                IOCTL_NVTOOL_READ_PRIV_REGISTERS,
                ReadPrivRegisters,
                NVTOOL_READ_PRIV_REGISTERS );
            break;
        }
        case IOCTL_NVTOOL_READ_PRIV_REGISTER:
        {
            NVTOOL_IOCTL(
                IOCTL_NVTOOL_READ_PRIV_REGISTER,
                ReadPrivRegister,
                NVTOOL_READ_PRIV_REGISTER );
            break;
        }
        case IOCTL_NVTOOL_WRITE_PRIV_REGISTER:
        {
            NVTOOL_IOCTL_NORETVAL(
                IOCTL_NVTOOL_WRITE_PRIV_REGISTER,
                WritePrivRegister,
                NVTOOL_WRITE_PRIV_REGISTER );
            break;
        }
        case IOCTL_NVTOOL_READ_PCICFG_REGISTER:
        {
            NVTOOL_IOCTL(
                IOCTL_NVTOOL_READ_PCICFG_REGISTER,
                ReadPciCfgRegister,
                NVTOOL_READ_PCICFG_REGISTER );
            break;
        }
        case IOCTL_NVTOOL_WRITE_PCICFG_REGISTER:
        {
            NVTOOL_IOCTL_NORETVAL(
                IOCTL_NVTOOL_WRITE_PCICFG_REGISTER,
                WritePciCfgRegister,
                NVTOOL_WRITE_PCICFG_REGISTER );
            break;
        }
        case IOCTL_NVTOOL_GET_DRIVER_VERSION:
        {
            NVTOOL_IOCTL(
                IOCTL_NVTOOL_GET_DRIVER_VERSION,
                GetDriverVersion,
                NVTOOL_DRIVER_VERSION );
            break;
        }
        case IOCTL_NVTOOL_GET_DEVICES:
        {
            NVTOOL_IOCTL_ARGS(
                IOCTL_NVTOOL_GET_DEVICES,
                GetDevices,
                NVTOOL_DEVICE_INFORMATION,
                NVTOOL_MAX_DEVICES );
            break;
        }
        case IOCTL_NVTOOL_GET_DEVICE_COUNT:
        {
            NVTOOL_IOCTL(
                IOCTL_NVTOOL_GET_DEVICE_COUNT,
                GetDeviceCount,
                NVTOOL_DEVICE_COUNT );
            break;
        }
        default:
        {
            pr_err(KERN_ERR "nvtool: cannot recognize ioctl code.\n");
            return (-EFAULT);
        }
    }

    return ret;
}

static int nvtool_open
(
    struct inode *inode,
    struct file *filp
)
{
    if ( g_DeviceOpened > 0 )
    {
        pr_err(KERN_INFO "nvtool has been opened %d time(s)\n", g_DeviceOpened );
        return -EBUSY;
    }
    DBG("nvtool aperture opened.\n");
    g_DeviceOpened++;

    return 0;
}

static int nvtool_release
(
    struct inode *inode,
    struct file *filp
)
{
    if ( g_DeviceOpened <= 0 )
    {
        return 0;
    }

    DBG("nvtool aperture closed.\n");
    g_DeviceOpened--;

    return 0;
}

static struct file_operations nvtool_fops =
{
    .owner          = THIS_MODULE,
    .open           = nvtool_open,
    .release        = nvtool_release,
    .write          = nvtool_write,
    .read           = nvtool_read,
    .unlocked_ioctl = nvtool_ioctl,
#if defined(HAVE_COMPAT_IOCTL)
	.compat_ioctl	= nvtool_ioctl,
#endif
};

static int __init nvtool_init( void )
{
    int ret;
    dev_t devno = 0;

    ret = InitializePciDriver();
    if ( ret < 0 )
    {
        printk(KERN_ERR "Register nvtool PCI device driver failed.\n");
        goto error_pci;
    }

    ret = alloc_chrdev_region( &devno, 0, DEVICE_NUMBER, NVTOOL_DEVICE_NAME );
    if ( ret < 0 )
    {
        printk(KERN_ERR "Error with allocating character device region.\n");
        goto error_cdev;
    }

    g_devno = devno;
    DBG( "Registered nvtool character device driver: major %d, minor %d\n", MAJOR(devno), MINOR(devno) );
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)) || defined(HAVE_CLASS_WITHOUT_OWNER)
    g_pClass = class_create( "chardrv" );
#else
    g_pClass = class_create( THIS_MODULE, "chardrv" );
#endif
    // Register the character device.
    if ( g_pClass == NULL )
    {
        printk(KERN_ERR "class_create failed\n");
        goto error_cdev;
    }

    if ( device_create( g_pClass, NULL, devno, NULL, NVTOOL_DEVICE_NAME ) == NULL )
    {
        printk(KERN_ERR "device_create failed\n");
        class_destroy( g_pClass );
        goto error_cdev;
    }

    cdev_init( &g_nvtool_cdev, &nvtool_fops );
    if ( cdev_add( &g_nvtool_cdev, devno, DEVICE_NUMBER ) < 0 )
    {
        printk(KERN_ERR "cdev_add failed\n");
        class_destroy( g_pClass );
        goto error_cdev;
    }

    printk( "nvtool driver loaded.\n" );
    return 0;

error_cdev:
    unregister_chrdev_region( devno, DEVICE_NUMBER );

error_pci:
    DeinitializePciDriver();
    return -1;
}

static void __exit nvtool_exit( void )
{
    dev_t devno = g_devno;

    DeinitializePciDriver();

    device_destroy( g_pClass, devno );
    class_destroy( g_pClass );

    unregister_chrdev_region( devno, DEVICE_NUMBER );
    cdev_del( &g_nvtool_cdev );

    printk( "nvtool driver unloaded.\n" );
}


module_init( nvtool_init );
module_exit( nvtool_exit );

#define STRINGIZE(str)                      #str
#define NVTOOL_VERSION(x, y, z)             STRINGIZE(x) "." STRINGIZE(y) "." STRINGIZE(z)
MODULE_VERSION( NVTOOL_VERSION( NVTOOL_VERSION_MAJOR, NVTOOL_VERSION_MINOR, NVTOOL_VERSION_PATCH ) );

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("NVIDIA");
MODULE_DESCRIPTION("nvtool kernel driver module");
