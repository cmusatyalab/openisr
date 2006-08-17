/*
                               Fauxide

		      A virtual disk drive tool
 
               Copyright (c) 2002-2004, Intel Corporation
                          All Rights Reserved

This software is distributed under the terms of the Eclipse Public License, 
Version 1.0 which can be found in the file named LICENSE.  ANY USE, 
REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
ACCEPTANCE OF THIS AGREEMENT

*/

/*                                                     
 * $Id: fauxide.c,v 1.9 2004/11/01 16:18:52 makozuch Exp $
 */


#ifndef __KERNEL__
#  define __KERNEL__
#endif
#ifndef MODULE
#  define MODULE
#endif

/* check for SMP */
#include <linux/config.h>
#ifdef CONFIG_SMP
#  define __SMP__
#endif

/* check versions */
#ifndef LINUX_VERSION_CODE
#  include <linux/version.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#  error "This kernel is too old: not supported by this file"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,18)
#  define NEW_GENDISK_HANDLING
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#  error "This kernel is too recent: not supported by this file"
#endif

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/init.h>

#include <asm/uaccess.h>

#define MAJOR_NR            fauxide_major /* force definitions on in blk.h */
static int fauxide_major = 0;     /* must be declared before including blk.h */

#define FAUXIDE_UNITS       4             /* Number of units per major */ 
#define FAUXIDE_PART_SHIFT  4
#define FAUXIDE_PARTS_PER_UNIT   (1 << FAUXIDE_PART_SHIFT) /* Parts per unit */

#define DEVICE_NR(device)   (MINOR(device) >> FAUXIDE_PART_SHIFT)
#define DEVICE_NAME         "fauxide"
#define DEVICE_REQUEST      fauxide_request
/* #define DEVICE_INTR fauxide_intrptr */ /* pointer to the bottom half */
#define DEVICE_NO_RANDOM                  /* no entropy to contribute */

#include <linux/blk.h>
#include <linux/blkpg.h>
#include <linux/hdreg.h>

#include "fauxide.h"

/*
 * DEFINES
 */

#define DEFAULT_MAJOR                   242

/* #define VERBOSE_DEBUG */
#define FAUXIDE_DEBUG(fmt, args...)     printk("[fauxide] " fmt, ## args)

#define FAUXIDE_ENABLE_RESCUE

typedef int vulpes_state_t;
#define VULPES_NO_PID                   -2
#define VULPES_INIT                     -1
#define VULPES_SLEEPING                 0
#define VULPES_BUSY                     1

typedef struct fauxide_device_t {
  vulpes_state_t vulpes_state; /* current state of vulpes */
  spinlock_t lock;
  vulpes_regblk_t vulpes_regblk;
  struct hd_driveid hw_id;
  int media_changed;
} fauxide_device;

/*
 * Prototypes
 */

int fauxide_open(struct inode *inode, struct file *filp);
int fauxide_release(struct inode *inode, struct file *filp);
int fauxide_ioctl(struct inode *inode, struct file *filp, 
		  unsigned cmd, unsigned long arg);
int fauxide_check_media_change(kdev_t dev);
int fauxide_revalidate(kdev_t dev);

/*
 * Globals
 */

const char *fauxide_version = "$Revision: 1.9 $";

int fauxide_major_request = DEFAULT_MAJOR;

struct block_device_operations fauxide_bdops = {
  open:               fauxide_open,
  release:            fauxide_release,
  ioctl:              fauxide_ioctl,
  check_media_change: fauxide_check_media_change,
  revalidate:         fauxide_revalidate,
  /*  owner:              THIS_MODULE, */
};

struct gendisk fauxide_gendisk = {
  major:              0,
  major_name:         "fi",
  minor_shift:        FAUXIDE_PART_SHIFT,
  max_p:              FAUXIDE_PARTS_PER_UNIT,
  fops:               &fauxide_bdops,
};

const unsigned char DEFAULT_HEADS=128;
const unsigned char DEFAULT_SECTORS=32;

MODULE_PARM(fauxide_major_request, "i");
MODULE_PARM_DESC(fauxide_major_request, "Major number to request for fauxide");

MODULE_DESCRIPTION("A pseudo-device for intercepting and redirecting ide requests.");
MODULE_AUTHOR("Michael Kozuch");

static int queue_initialized = 0;

static fauxide_device * fauxide_device_array = NULL;
static struct hd_struct *fauxide_partition_array = NULL;
static int *fauxide_blk_sizes = NULL;
static int *fauxide_blksize_sizes = NULL;
static int *fauxide_max_sectors = NULL;

static spinlock_t fauxide_request_special_lock;

/*
 * Auxiliary functions
 */

static inline 
int no_vulpes(const fauxide_device *dev)
{
  return (dev->vulpes_state == VULPES_NO_PID);
}

static inline 
int fauxide_get_device_num(struct inode *inode)
{
  return DEVICE_NR(inode->i_rdev);
}

static inline
fauxide_device* fauxide_get_device_from_kdev(kdev_t kdev)
{
  fauxide_device *dev = NULL;

  dev = fauxide_device_array + (int)MINOR(kdev);

  return dev;
}

static inline 
fauxide_device *fauxide_get_device_from_request(const struct request *req)
{
  int num;

  num = DEVICE_NR(req->rq_dev);
  
  return (num < (FAUXIDE_UNITS*FAUXIDE_PARTS_PER_UNIT)) 
    ? (fauxide_device_array+num) 
    : NULL;
}

static inline 
fauxide_device *fauxide_get_device(struct inode *inode)
{
  int num;
  
  num=fauxide_get_device_num(inode);

  return (num < (FAUXIDE_UNITS*FAUXIDE_PARTS_PER_UNIT)) 
    ? (fauxide_device_array+num) 
    : NULL;
}

#ifndef NEW_GENDISK_HANDLING
static void fauxide_scan_gendisk_array(void)
{
  struct gendisk *gendisk_ptr;
  
  FAUXIDE_DEBUG("BEGIN *** gendisk_scan() ***\n");
  gendisk_ptr = gendisk_head;
  while(gendisk_ptr!=NULL) {
    FAUXIDE_DEBUG("gendisk_scan() found %s\n",gendisk_ptr->major_name);
    gendisk_ptr = gendisk_ptr->next;
  }
  FAUXIDE_DEBUG("END *** gendisk_scan() ***\n");
}
#endif

static void fauxide_print_block_major_stats(int major, int minor)
{
  /* WARNING: This function does NO checking for valid major, minor */

  printk("fauxide: *** block_major_stats(%d, %d) ***\n", major, minor);

  /* blk_size[][] */
  if(!blk_size[major]) {
    printk("fauxide: blk_size[%d] is NULL. (no checking)\n", major);
  } else {
    printk("fauxide: blk_size[%d][%d] = %d KB.\n", major, minor, 
	   blk_size[major][minor]);
  }

  /* blksize_size[][] */
  if(!blksize_size[major]) {
    printk("fauxide: blksize_size[%d] is NULL. (%d assumed)\n", major, 
	   BLOCK_SIZE);
  } else {
    printk("fauxide: blksize_size[%d][%d] = %d bytes.\n", major, minor, 
	   blksize_size[major][minor]);
  }

  /* hardsect_size[][] */
  if(!hardsect_size[major]) {
    printk("fauxide: hardsect_size[%d] is NULL. (512 assumed)\n", major);
  } else {
    printk("fauxide: hardsect_size[%d][%d] = %d bytes.\n", major, minor, 
	   hardsect_size[major][minor]);
  }

  /* read_ahead[] */
  printk("fauxide: read_ahead[%d] = %d sectors.\n", major, read_ahead[major]);

  /* max_readahead[][] */
  if(!max_readahead[major]) {
    printk("fauxide: max_readahead[%d] is NULL.\n", major);
  } else {
    printk("fauxide: max_readahead[%d][%d] = %d sectors.\n", major, minor, 
	   max_readahead[major][minor]);
  }

  /* max_sectors[][] */
  if(!max_sectors[major]) {
    printk("fauxide: max_sectors[%d] is NULL.\n", major);
  } else {
    printk("fauxide: max_sectors[%d][%d] = %d sectors.\n", major, minor, 
	   max_sectors[major][minor]);
  }

  printk("fauxide: *** done ***\n");
}

/* Set up and allocate device data and arrays */
static int fauxide_allocate_data(void)
{
  const int fauxide_blksize_size_default = VULPES_CMDBLK_BUFSIZE;  /* bytes */
  const int fauxide_read_ahead_default = VULPES_CMDBLK_SECT_PER_BUF;       /* sectors */
  const int fauxide_max_sectors_default = VULPES_CMDBLK_SECT_PER_BUF;      /* sectors */

  unsigned total_parts = (FAUXIDE_UNITS*FAUXIDE_PARTS_PER_UNIT);
  int i;

  fauxide_blk_sizes = kmalloc(total_parts * sizeof(int), GFP_KERNEL);
  if (!fauxide_blk_sizes)
    goto fail_malloc;
  memset(fauxide_blk_sizes, 0, total_parts*sizeof(int));
  blk_size[fauxide_major]=fauxide_blk_sizes;

  fauxide_blksize_sizes = kmalloc(total_parts*sizeof(int), GFP_KERNEL);
  if (!fauxide_blksize_sizes)
    goto fail_malloc;
  for (i=0; i < total_parts; i++) /* all the same blocksize */
    fauxide_blksize_sizes[i] = fauxide_blksize_size_default;
  blksize_size[fauxide_major]=fauxide_blksize_sizes;

  hardsect_size[fauxide_major] = NULL;

  read_ahead[fauxide_major] = fauxide_read_ahead_default;
  max_readahead[fauxide_major] = NULL;

  fauxide_max_sectors = kmalloc(total_parts * sizeof(int), GFP_KERNEL);
  if (!fauxide_max_sectors)
    goto fail_malloc;
  for (i=0; i < total_parts; i++) /* all the same blocksize */
    fauxide_max_sectors[i] = fauxide_max_sectors_default;
  max_sectors[fauxide_major]=fauxide_max_sectors;

  /* Allocate the gendisk.part array */
  fauxide_partition_array = kmalloc(total_parts*sizeof(struct hd_struct), GFP_KERNEL);
  if(!fauxide_partition_array)
    goto fail_malloc;
  memset(fauxide_partition_array, 0, total_parts*sizeof(struct hd_struct));
  
  fauxide_gendisk.part = fauxide_partition_array;
  fauxide_gendisk.nr_real = FAUXIDE_UNITS;
  fauxide_gendisk.sizes = fauxide_blk_sizes;

  /* Add fauxide_gendisk to the list */
#ifdef NEW_GENDISK_HANDLING
  add_gendisk(&fauxide_gendisk);
#else
  fauxide_gendisk.next = gendisk_head;
  gendisk_head = &fauxide_gendisk;
#endif

  /* Allocate the device structs */
  fauxide_device_array = kmalloc(FAUXIDE_UNITS * sizeof (fauxide_device), GFP_KERNEL);
  if (!fauxide_device_array)
    goto fail_malloc;
  memset(fauxide_device_array, 0, FAUXIDE_UNITS * sizeof (fauxide_device));
  for(i=0; i<FAUXIDE_UNITS; i++) {
    spin_lock_init(&fauxide_device_array[i].lock);
    fauxide_device_array[i].vulpes_regblk.reg.pid = (pid_t)0;
    fauxide_device_array[i].vulpes_state = VULPES_NO_PID;
    fauxide_device_array[i].media_changed = 1;
  }

  return 0;

fail_malloc:
  return -ENOMEM;
}

static void fauxide_free_data(void)
{
  if(fauxide_device_array) {
    kfree(fauxide_device_array);
    fauxide_device_array = NULL;
  }

  if(fauxide_blk_sizes) {
    blk_size[fauxide_major] = NULL;
    kfree(fauxide_blk_sizes);
    fauxide_blk_sizes = NULL;
  }

  if(fauxide_blksize_sizes) {
    blksize_size[fauxide_major] = NULL;
    kfree(fauxide_blksize_sizes);
    fauxide_blksize_sizes = NULL;
  }

  if(fauxide_max_sectors) {
    max_sectors[fauxide_major] = NULL;
    kfree(fauxide_max_sectors);
    fauxide_max_sectors = NULL;
  }

  if(fauxide_partition_array) {
    fauxide_gendisk.part = NULL;
    kfree(fauxide_partition_array);
    fauxide_partition_array = NULL;
  }

  /* Remove our gendisk from the kernel list */
#ifdef NEW_GENDISK_HANDLING
  del_gendisk(&fauxide_gendisk);
#else
  done = 0;
  if(gendisk_head == &fauxide_gendisk) {
    gendisk_head = fauxide_gendisk.next;
    done = 1;
  } else {
    gendisk_ptr = gendisk_head;
    while(!done && (gendisk_ptr!=NULL)) {
      /* FAUXIDE_DEBUG("gendisk unload found %s\n",gendisk_ptr->major_name); */
      if(gendisk_ptr->next == &fauxide_gendisk) {
	gendisk_ptr->next = fauxide_gendisk.next;
	done = 1;
      } else {
	gendisk_ptr = gendisk_ptr->next;
      }
    }
    if(gendisk_ptr==NULL)
      printk(KERN_WARNING "fauxide: failed to locate gendisk.\n");
  }
#endif
}

/* Register device and return major number */
static int fauxide_register_device(void)
{
  int result = 0;

  /* Request a major device number */
  result = register_blkdev(fauxide_major_request, "fauxide", &fauxide_bdops);

  /* If the requested number was static, success yields zero */
  if((fauxide_major_request > 0) && (result == 0))
    result = fauxide_major_request;

  /* Record in gendisk struct */
  fauxide_gendisk.major = result;

  return result;
}

static void fauxide_initialize_hw_id(fauxide_device *dev)
{
  struct hd_driveid *id;
  unsigned long totalsectors;
  unsigned long cylinders;

  id = &(dev->hw_id);

  /* Assumes that dev->vulpes_regblk.reg.volsize is valid */

  memset(id, 0, sizeof(*id));

  totalsectors = dev->vulpes_regblk.reg.volsize;

  cylinders = totalsectors / (DEFAULT_HEADS*DEFAULT_SECTORS)
    + ((totalsectors % (DEFAULT_HEADS*DEFAULT_SECTORS)) ? 1 : 0);

  id->cyls = id->cur_cyls = cylinders;
  id->heads = id->cur_heads = DEFAULT_HEADS;
  /* Partho: This fixes the cylinder calculation bug!! :)
  id->sectors = id->cur_sectors = (DEFAULT_SECTORS - 1);*/
  id->sectors = id->cur_sectors = (DEFAULT_SECTORS);

  id->sector_bytes = FAUXIDE_HARDSECT_SIZE;
  id->track_bytes = DEFAULT_SECTORS * FAUXIDE_HARDSECT_SIZE;

  id->vendor0 = 0x8086;

  memcpy(id->serial_no, "01234567890123456789", 20);
  memcpy(id->model, "Fauxide 10000", 14);
  memcpy(id->fw_rev, "01-02-03", 8);

  id->capability = 0x3; /* 0:DMA 1:LBA */
  id->field_valid = 1;

  id->cur_capacity0 = (unsigned short)(totalsectors & 0xFFFF);
  id->cur_capacity1 = (unsigned short)(totalsectors >> 16);

  id->lba_capacity = totalsectors;

  id->major_rev_num = 0x7;
  id->minor_rev_num = 0x0;
}

static void fauxide_register_disk(int devnum, fauxide_device *dev)
{
  FAUXIDE_DEBUG("fauxide_register_disk(%d) ...\n", devnum);
  dev->vulpes_state = VULPES_INIT;
  register_disk(&fauxide_gendisk, 
		MKDEV(fauxide_major, devnum*FAUXIDE_PARTS_PER_UNIT),
		FAUXIDE_PARTS_PER_UNIT, &fauxide_bdops, 
		(long)(dev->vulpes_regblk.reg.volsize));
  dev->vulpes_state = VULPES_SLEEPING;
  FAUXIDE_DEBUG("  ... fauxide_register_disk(%d) done.\n", devnum);

  /* special_lock was grabbed by request()  */
  spin_unlock(&fauxide_request_special_lock);
}

static void fauxide_reread_pt(int devnum, fauxide_device *dev)
{
  int start, numparts;

  spin_lock(&dev->lock);

  /* Clear old information -- but not the unit information*/
  start = devnum*FAUXIDE_PARTS_PER_UNIT + 1;
  numparts = FAUXIDE_PARTS_PER_UNIT - 1;
  memset(&fauxide_blk_sizes[start], 0, numparts*sizeof(int));
  memset(&fauxide_partition_array[start],0,numparts*sizeof(struct hd_struct));

  fauxide_register_disk(devnum, dev);

  spin_unlock(&dev->lock);
}

static void 
fauxide_ioctl_register(int devnum, fauxide_device *dev, void *user_ptr)
{
  spin_lock(&dev->lock);

  copy_from_user(&dev->vulpes_regblk, (vulpes_regblk_t*)user_ptr, 
		 sizeof(vulpes_regblk_t));

  FAUXIDE_DEBUG("ioctl(%d). REGISTERED pid %d\n", 
		devnum, (int)(dev->vulpes_regblk.reg.pid));

  /* Clear old information */
  memset(&fauxide_blk_sizes[devnum*FAUXIDE_PARTS_PER_UNIT], 0, 
	 FAUXIDE_PARTS_PER_UNIT*sizeof(int));
  memset(&fauxide_partition_array[devnum*FAUXIDE_PARTS_PER_UNIT], 0, 
	 FAUXIDE_PARTS_PER_UNIT*sizeof(struct hd_struct));

  /* Fill in unit information */
  fauxide_blk_sizes[devnum*FAUXIDE_PARTS_PER_UNIT] = fauxide_device_array[devnum].vulpes_regblk.reg.volsize / FAUXIDE_SECTORS_PER_KB;
  fauxide_partition_array[devnum*FAUXIDE_PARTS_PER_UNIT].nr_sects = fauxide_device_array[devnum].vulpes_regblk.reg.volsize;

  /* Indicate that the media changed */
  dev->media_changed = 1;

  fauxide_initialize_hw_id(dev);

  fauxide_register_disk(devnum, dev);

  spin_unlock(&dev->lock);
}

static int
fauxide_ioctl_unregister(int devnum, fauxide_device *dev, void *user_ptr)
{
  vulpes_registration_t tmp;
  int result = 0;

  spin_lock(&dev->lock);
  copy_from_user(&tmp, (vulpes_registration_t*)user_ptr, 
		 sizeof(vulpes_registration_t));

  /* Indicate that the media changed */
  dev->media_changed = 1;

  if(tmp.pid == dev->vulpes_regblk.reg.pid) {
    dev->vulpes_regblk.reg.pid = (pid_t)0;
    dev->vulpes_state = VULPES_NO_PID;
    /* Should sync here before letting vulpes go.  Something like...
       for(i=devnum; i<(devnum+FAUXIDE_PARTS_PER_UNIT); i++)
       fsync_dev(MKDEV(fauxide_major, i));
    */
    FAUXIDE_DEBUG("ioctl(%d). UNREGISTERED pid %d\n", 
		  devnum, (int)tmp.pid);
  } else {
    FAUXIDE_DEBUG("ioctl(%d). failed to UNREGISTER pid %d. old pid=%d\n", 
		  devnum, (int)tmp.pid, (int)(dev->vulpes_regblk.reg.pid));
    result = -EINVAL;
  }
  spin_unlock(&dev->lock);

  return result;
}

static void fauxide_process_ioctl_cmdblk(fauxide_device *dev, void *user_ptr)
{
  vulpes_cmd_head_t head;
  unsigned long flags;
  int request_status = 0xdeadbeef;
  int get_next = 0;
  int gotosleep = 0;

  spin_lock(&dev->lock);

  copy_from_user(&head, &((vulpes_cmdblk_t*)user_ptr)->head, sizeof(vulpes_cmd_head_t));

#ifdef VERBOSE_DEBUG
  FAUXIDE_DEBUG("process_cmdblk(%#x) start=%lu num=%lu.\n", (int)head.cmd, 
		(unsigned long)head.start_sect, (unsigned long)head.num_sect);
#endif

  spin_lock_irqsave(&io_request_lock, flags);

  /* Complete the current command */
  switch(head.cmd) {
  case VULPES_CMD_READ_DONE:
    if(head.fauxide_id == CURRENT->buffer) {
      if(head.num_sect == CURRENT->current_nr_sectors) {
	copy_from_user(CURRENT->buffer, ((vulpes_cmdblk_t*)user_ptr)->buffer, 
		       head.num_sect*FAUXIDE_HARDSECT_SIZE);
      } else {
	FAUXIDE_DEBUG("process_cmdblk(read_done) bad nr_sect.\n");
      }
      request_status = 1;
      get_next = 1;
    } else {
      FAUXIDE_DEBUG("process_cmdblk(read_done) id mismatch.\n");
      get_next = 1;
    }
    break;
  case VULPES_CMD_WRITE_DONE:
    if(head.fauxide_id == CURRENT->buffer) {
      request_status = 1;
      get_next = 1;
    } else {
      FAUXIDE_DEBUG("process_cmdblk(write_done) id mismatch.\n");
      get_next = 1;
    }
    break;
  case VULPES_CMD_GET:
    get_next = 1;
    break;
  case VULPES_CMD_ERROR:
    request_status = 0;
    get_next = 1;
    break;
  default:
    /* This should probably be fatal */
    FAUXIDE_DEBUG("process_cmdblk() unknown command (%d).\n", head.cmd);
    get_next = 1;
  }

  /* End the current request */
  if(request_status == 1) {
    end_request(1);
  } else if(request_status == 0) {
    end_request(0);
  }

  /* No need to set head.vulpes_id because it is already set */

  /* Get the next command */
  if(get_next) {
    if(! QUEUE_EMPTY) {
      fauxide_device *tmp_dev;
      tmp_dev = fauxide_get_device_from_request(CURRENT);
      if(tmp_dev->vulpes_regblk.reg.pid == dev->vulpes_regblk.reg.pid) {
	int minor;
	head.vulpes_id = tmp_dev->vulpes_regblk.reg.vulpes_id;
	minor = MINOR(CURRENT->rq_dev);
	if(CURRENT->cmd == WRITE) {
	  head.cmd = VULPES_CMD_WRITE;
	  head.start_sect = CURRENT->sector + fauxide_partition_array[minor].start_sect;
	  head.num_sect = CURRENT->current_nr_sectors;
	  head.fauxide_id = CURRENT->buffer;
	  if(head.num_sect > VULPES_CMDBLK_SECT_PER_BUF) {
	    FAUXIDE_DEBUG("process_cmdblk() writing too much (%llu).\n", 
			  (unsigned long long)(head.num_sect));	    
	    head.num_sect = VULPES_CMDBLK_SECT_PER_BUF;
	  }
	  copy_to_user(((vulpes_cmdblk_t*)user_ptr)->buffer, CURRENT->buffer, 
		       head.num_sect*FAUXIDE_HARDSECT_SIZE);
	  /* begin: ugly hack to update part table */
	  if(head.start_sect == 0) {
	    int n;
	    n = (CURRENT->current_nr_sectors > VULPES_CMDBLK_SECT_PER_BUF)
		 ? VULPES_CMDBLK_SECT_PER_BUF : CURRENT->current_nr_sectors;
	    memcpy(tmp_dev->vulpes_regblk.buffer, CURRENT->buffer, 
		   n*FAUXIDE_HARDSECT_SIZE);
	  }
	  /* end: ugly hack */
	} else if(CURRENT->cmd == READ) {
	  head.cmd = VULPES_CMD_READ;
	  head.start_sect = CURRENT->sector + fauxide_partition_array[minor].start_sect;
	  head.num_sect = CURRENT->current_nr_sectors;
	  head.fauxide_id = CURRENT->buffer;
	  if(head.num_sect > VULPES_CMDBLK_SECT_PER_BUF) {
	    FAUXIDE_DEBUG("process_cmdblk() reading too much (%llu).\n", 
			  (unsigned long long)(head.num_sect));	    
	  }
	} else {
	  /* This should probably be fatal */
	  FAUXIDE_DEBUG("process_cmdblk() unknown current->command (%d).\n", 
			CURRENT->cmd);
	  gotosleep = 1; /* not sure what else to do */
	}
      } else {
	gotosleep = 1;
      }
    } else {
      gotosleep = 1;
    }
    
    if(gotosleep) {
      head.cmd = VULPES_CMD_SLEEP;
      head.fauxide_id = NULL;
      dev->vulpes_state = VULPES_SLEEPING;
    } else {
      dev->vulpes_state = VULPES_BUSY;
    }

    copy_to_user(&((vulpes_cmdblk_t*)user_ptr)->head, &head, sizeof(vulpes_cmd_head_t));
  }

  spin_unlock_irqrestore(&io_request_lock, flags);

#ifdef VERBOSE_DEBUG
  FAUXIDE_DEBUG("   ... next cmd=%#x start=%lu num=%lu.\n", (int)head.cmd, 
		(unsigned long)head.start_sect, (unsigned long)head.num_sect);
#endif

  spin_unlock(&dev->lock);
}

static int fauxide_send_vulpes_signal(fauxide_device *dev)
{
  int err;

  if(no_vulpes(dev)) return -ESRCH;

  err = kill_proc_info(SIGUSR1, (void*) 1, dev->vulpes_regblk.reg.pid);

  return err;
}

/*
 * Interface functions
 */

int fauxide_open(struct inode *inode, struct file *filp)
{
  int num;

  num = fauxide_get_device_num(inode);

  FAUXIDE_DEBUG("open(%d).\n", num);

  /* 
   * IMPORTANT: There seems to be a potential deadlock due to Linux shared I/O 
   *   buffers in which kernel memory management threads block trying to flush 
   *   data to the fauxide device which, in turn, waits on teh user-level 
   *   vulpes process, which is blocked trying to write to disk (or file system).
   *   Due to Linux page cache operation, this can not continue until the 
   *   kernel threads progress.  The work-around is to avoid large amounts of 
   *   data in the cache that need to be flushed to fauxide by bdflush.
   *   By forcing the file descriptors to O_SYNC, we avoid leaving dirty data 
   *   in the cache.  
   * WARNING: This work-around does not work if the fauxide device is opened 
   *   indirectly (by being mem-mapped or mounting file systems on the device.
   */
  filp->f_flags |= O_SYNC;

  MOD_INC_USE_COUNT;

  return 0;
}

int fauxide_release(struct inode *inode, struct file *filp)
{
  int num;

  num = fauxide_get_device_num(inode);

  MOD_DEC_USE_COUNT;

  FAUXIDE_DEBUG("release(%d).\n", num);

  return 0;
}

int fauxide_ioctl(struct inode *inode, struct file *filp, 
		  unsigned cmd, unsigned long arg)
{
  int err = 0;
  int result = 0;

  int num;
  fauxide_device *dev;

  unsigned ioctl_type;

  num = fauxide_get_device_num(inode);
  dev = fauxide_get_device(inode);

#ifdef VERBOSE_DEBUG
  FAUXIDE_DEBUG("ioctl(%d). cmd=%#x arg=%lu\n", num, cmd, arg);
#endif

  if(!dev) {
    FAUXIDE_DEBUG("ioctl(%d). bad device num %d\n", num, num);
    return -ENODEV;
  }

  if(no_vulpes(dev)) {
    if(cmd == FAUXIDE_IOCTL_REGBLK_REGISTER) {
      err = ! access_ok(VERIFY_READ, arg, sizeof(vulpes_regblk_t));
      if (err) return -EFAULT;
      fauxide_ioctl_register(num, dev, (void*)arg);
    }
#ifdef FAUXIDE_ENABLE_RESCUE
    else if(cmd == FAUXIDE_IOCTL_RESCUE) {
      while(MOD_IN_USE)
	MOD_DEC_USE_COUNT;
      MOD_INC_USE_COUNT;
    }
#endif
    else {
      FAUXIDE_DEBUG("ioctl(%d). vulpes unregistered.  cmd=%#x arg=%lu\n", 
		    num, cmd, arg);
      result = -ENOTTY;
    }
  } else {

    ioctl_type = _IOC_TYPE(cmd);

    if(ioctl_type ==  _FAUXIDE_IOCTL_TYPE) {
      switch(cmd) {
      case FAUXIDE_IOCTL_CMDBLK:
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(vulpes_cmdblk_t));
	if (err) return -EFAULT;
	fauxide_process_ioctl_cmdblk(dev, (void*)arg);
	break;
      case FAUXIDE_IOCTL_REGBLK_UNREGISTER:
	err = ! access_ok(VERIFY_READ, arg, sizeof(vulpes_registration_t));
	if (err) return -EFAULT;
	result = fauxide_ioctl_unregister(num, dev, (void*)arg);
	break;
      case FAUXIDE_IOCTL_REGBLK_REGISTER:
	err = ! access_ok(VERIFY_READ, arg, sizeof(vulpes_registration_t));
	if (err) return -EFAULT;
	spin_lock(&dev->lock);
	{
	  vulpes_registration_t tmp;
	  copy_from_user(&tmp, (vulpes_registration_t*)arg, 
			 sizeof(vulpes_registration_t));
	  FAUXIDE_DEBUG("ioctl(%d). failed to REGISTER pid %d. old pid=%d\n", 
			num, (int)tmp.pid, (int)(dev->vulpes_regblk.reg.pid));
	  result = -EINVAL;
	}
	spin_unlock(&dev->lock);
	break;	
      case FAUXIDE_IOCTL_TEST_SIGNAL:
	spin_lock(&dev->lock);
	err = fauxide_send_vulpes_signal(dev);
	spin_unlock(&dev->lock);
	if(err) {
	  FAUXIDE_DEBUG("ioctl(%d). TEST_SIGNAL failed %d.\n", num, err);
	  result = err;
	} else {
	  FAUXIDE_DEBUG("ioctl(%d). TEST_SIGNAL\n", num);
	}
	break;
#ifdef FAUXIDE_ENABLE_RESCUE
      case FAUXIDE_IOCTL_RESCUE:
	while(MOD_IN_USE)
	  MOD_DEC_USE_COUNT;
	MOD_INC_USE_COUNT;
	break;
#endif
      default:
	FAUXIDE_DEBUG("ioctl(%d). unknown fauxide cmd=%#x arg=%lu\n", 
		      num, cmd, arg);
	result = -ENOTTY;
      }
    } else if(ioctl_type ==  0x12) { /* Block device ioctl */
      long size;

      switch(cmd) {
      case BLKGETSIZE: 
	FAUXIDE_DEBUG("ioctl(%d). BLKGETSIZE\n", num);
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(long));
	if (err) return -EFAULT;
	size = fauxide_gendisk.part[MINOR(inode->i_rdev)].nr_sects;
	if(copy_to_user((long*)arg, &size, sizeof(long))) return -EFAULT;
	break;
      case BLKRRPART:
	FAUXIDE_DEBUG("ioctl(%d). BLKRRPART\n", num);
 	fauxide_reread_pt(num, dev);
	break;
      default:
	FAUXIDE_DEBUG("ioctl(%d). accepting unknown blk_ioctl cmd=%#x arg=%lu\n", 
		      num, cmd, arg);
	result = blk_ioctl(inode->i_rdev, cmd, arg);
      }
    } else if(ioctl_type ==  0x3) { /* hard disk ioctl */
      long totalsectors;
      long cylinders;

      switch(cmd) {
      case HDIO_GET_IDENTITY: {
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(struct hd_driveid));
	if (err) return -EFAULT;
	FAUXIDE_DEBUG("ioctl(%d). HDIO_GET_IDENTITY\n", num);
	if(copy_to_user((struct hd_driveid*)arg, &(dev->hw_id), 
			sizeof(dev->hw_id))) 
	   return -EFAULT;
	break;
      }
      case HDIO_GETGEO: {
	struct hd_geometry geo;
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(geo));
	if (err) return -EFAULT;
	totalsectors = fauxide_gendisk.part[MINOR(inode->i_rdev)].nr_sects;
	cylinders = totalsectors / (DEFAULT_HEADS*DEFAULT_SECTORS)
	  + ((totalsectors % (DEFAULT_HEADS*DEFAULT_SECTORS)) ? 1 : 0);
	if(cylinders > 1024) {
	  printk(KERN_WARNING "fauxide: ioctl(HDIO_GETGEO) calculated %ld cylinders.\n", cylinders);
	}
	geo.heads = DEFAULT_HEADS;
	geo.sectors = DEFAULT_SECTORS;
	geo.cylinders = cylinders;
	geo.start = fauxide_gendisk.part[MINOR(inode->i_rdev)].start_sect;
	FAUXIDE_DEBUG("ioctl(%d). HDIO_GETGEO returning c=%u h=%u s=%u start=%lu\n", num, geo.cylinders, (unsigned)geo.heads, (unsigned)geo.sectors, geo.start);
	if(copy_to_user((struct hd_geometry*)arg, &geo, sizeof(geo))) 
	   return -EFAULT;
	break;
      }
      case HDIO_GETGEO_BIG: {
	struct hd_big_geometry big;
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(big));
	totalsectors = fauxide_gendisk.part[MINOR(inode->i_rdev)].nr_sects;
	cylinders = totalsectors / (DEFAULT_HEADS*DEFAULT_SECTORS)
	  + ((totalsectors % (DEFAULT_HEADS*DEFAULT_SECTORS)) ? 1 : 0);
	if(cylinders > 1024) {
	  printk(KERN_WARNING "fauxide: ioctl(HDIO_GETGEO_BIG) calculated %ld cylinders.\n", cylinders);
	}
	big.heads = DEFAULT_HEADS;
	big.sectors = DEFAULT_SECTORS;
	big.cylinders = cylinders;
	big.start = fauxide_gendisk.part[MINOR(inode->i_rdev)].start_sect;
	FAUXIDE_DEBUG("ioctl(%d). HDIO_GETGEO returning c=%u h=%u s=%u start=%lu\n", num, big.cylinders, (unsigned)big.heads, (unsigned)big.sectors, big.start);
	if(copy_to_user((struct hd_big_geometry*)arg, &big, sizeof(big))) 
	   return -EFAULT;
	break;
      }
      default:
	FAUXIDE_DEBUG("ioctl(%d). unknown hdio cmd=%#x arg=%lu\n", 
		      num, cmd, arg);
	result = -ENOTTY;
      }
    } else {
      FAUXIDE_DEBUG("ioctl(%d). unknown cmd=%#x arg=%lu\n", 
		    num, cmd, arg);
      result = -ENOTTY;
    }
  }

  return result;
}

int fauxide_check_media_change(kdev_t kdev)
{
  int result;
  fauxide_device *dev = NULL;

  dev = fauxide_get_device_from_kdev(kdev);

  result = dev->media_changed;

  FAUXIDE_DEBUG("check_media_change(%d).\n", (int)MINOR(kdev));

  /* Indicate that the media changed */
  dev->media_changed = 0;

  return result;
}

int fauxide_revalidate(kdev_t kdev)
{
  int devnum;
  fauxide_device *dev = NULL;

  dev = fauxide_get_device_from_kdev(kdev);

  devnum = (int)MINOR(kdev);

  FAUXIDE_DEBUG("revalidate(%d).\n", (int)MINOR(kdev));

  fauxide_reread_pt(devnum, dev);

  return 0;
}

void fauxide_request(request_queue_t *q)
{
  fauxide_device *dev = NULL;
    
#ifdef VERBOSE_DEBUG
  FAUXIDE_DEBUG("request()\n");
#endif
  
  INIT_REQUEST;  /* returns when queue is empty */
  
#ifdef VERBOSE_DEBUG
  FAUXIDE_DEBUG("request: cmd=%i sec=%lu nr=%lu.\n",
		(int)CURRENT->cmd, (unsigned long)CURRENT->sector, 
		(unsigned long)CURRENT->current_nr_sectors);
#endif
  
  /* Which "device" are we using? */
  dev = fauxide_get_device_from_request(CURRENT);
  if (dev == NULL) {
    printk(KERN_WARNING "fauxide: unknown device in fauxide_request().\n");
    end_request(0);
    return;
  }
  
  /* Check for special init time request */
  spin_lock(&fauxide_request_special_lock);
  if(dev->vulpes_state == VULPES_INIT) { /* this value is only set by 
					  register() while dev->lock is held */
    /* if true, keep special_lock through return to register(), it will
       be released there */
    FAUXIDE_DEBUG("INIT.\n");
    do {
      if((CURRENT->cmd == READ) && 
	 ((CURRENT->sector + CURRENT->current_nr_sectors) 
	  <= VULPES_REGBLK_SECT_PER_BUF)) {
	memcpy(CURRENT->buffer, dev->vulpes_regblk.buffer, 
	       (CURRENT->current_nr_sectors * FAUXIDE_HARDSECT_SIZE));
	end_request(1);
      } else {
	printk(KERN_WARNING "fauxide: bad request during init in fauxide_request().\n");
	end_request(0);
	return;
      }

      INIT_REQUEST;  /* returns when queue is empty */
    } while(1);
    return;
  }
  spin_unlock(&fauxide_request_special_lock);

  /* Perform the transfer and clean up. */
  spin_lock(&dev->lock);
  if(no_vulpes(dev)) {
    printk(KERN_WARNING "fauxide: unregistered device in fauxide_request().\n");
    end_request(0);
  }
  /* TODO: the following test is bogus.  We need to check if the process is 
     sleeping.  If more than one dev is served by the same pid, we have a
     problem. */
  else if(dev->vulpes_state == VULPES_SLEEPING) {
    int err;
    err = fauxide_send_vulpes_signal(dev);
    if(err) {
      FAUXIDE_DEBUG("request: signal send failed (%d).\n", err);
    }
  } /* If vulpes is busy, we'll catch the request when the current one completes */
  spin_unlock(&dev->lock);
 
  return;
}


void fauxide_cleanup(void)  
{
  int i;

  FAUXIDE_DEBUG("cleanup.\n");

  /* fsync - pg 359 */
  for(i=0; i<(FAUXIDE_UNITS*FAUXIDE_PARTS_PER_UNIT); i++)
    fsync_dev(MKDEV(fauxide_major, i));

  unregister_blkdev(fauxide_major, "fauxide");

  if(queue_initialized) {
    blk_cleanup_queue(BLK_DEFAULT_QUEUE(fauxide_major));
    queue_initialized=0;
  }

  fauxide_free_data();
}

int fauxide_init(void)      
{ 
  int result;

  /* Register device */
  result = fauxide_register_device();
  if(result < 0) {
    printk(KERN_WARNING "fauxide: init(). can't get major %d.  result=%d.\n", 
	   fauxide_major_request, result);
    return result;
  } else {
    fauxide_major = result;
  }

  FAUXIDE_DEBUG("init(MAJOR_NR=%d).  %s [%s %s]\n", 
		MAJOR_NR, fauxide_version, __DATE__, __TIME__); 

  /* Allocate the arrays */
  result = fauxide_allocate_data();  
  if(result) {
    fauxide_cleanup();
    return result;
  }

  spin_lock_init(&fauxide_request_special_lock);

  /* initialize the queue */
  blk_init_queue(BLK_DEFAULT_QUEUE(fauxide_major), fauxide_request);
  queue_initialized = 1;

  return 0; 
}



module_init(fauxide_init);
module_exit(fauxide_cleanup);


MODULE_LICENSE("ECLIPSE");
