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

#ifndef __KERNEL__
#  define __KERNEL__
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <linux/hdreg.h>

#include "fauxide.h"

MODULE_LICENSE("ECLIPSE");
static char *Version = "$Revision: 1.13 $";

/*
 * DEFINES
 */

#define DEFAULT_MAJOR                   242

const unsigned char DEFAULT_HEADS=128;
const unsigned char DEFAULT_SECTORS=32;

static int major_num=DEFAULT_MAJOR;

typedef int vulpes_state_t;
#define VULPES_NO_PID                   -2
#define VULPES_INIT                     -1
#define VULPES_SLEEPING                 0
#define VULPES_BUSY                     1

/* #define VERBOSE_DEBUG */
#define ISR_DEBUG(fmt, args...)     printk("[isr] " fmt, ## args)

/*
 * Our request queue.
 */
static struct request_queue *Queue;

/*
 * The internal representation of our device.
 */
static struct isr_device {
    vulpes_state_t vulpes_state; /* current state of vulpes */
    spinlock_t lock;
    spinlock_t iolock;
    vulpes_regblk_t vulpes_regblk;
    struct hd_driveid hw_id;
    int media_changed;
    struct gendisk *gd;
} Device;

static spinlock_t isr_request_special_lock;

/* Defined below */
static struct block_device_operations isr_ops;

static inline int no_vulpes(const struct isr_device *dev)
{
  return (dev->vulpes_state == VULPES_NO_PID);
}

static int isr_send_vulpes_signal(struct isr_device *dev)
{
  int err;

  if(no_vulpes(dev)) return -ESRCH;

  /* err = kill_proc_info(SIGUSR1, (void*) 1, dev->vulpes_regblk.reg.pid); */
  err = kill_proc(dev->vulpes_regblk.reg.pid, SIGUSR1, (void*) 1);

  return err;
}

static inline 
struct isr_device *isr_get_device_from_request(const struct request *req)
{
    return (struct isr_device*)req->rq_disk->private_data;
}

/*
 * Handle an I/O request.
 */
static void isr_request(request_queue_t *q)
{
    struct request *req;

    /* XXX: do we need to check for correct device ? */

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("isr_request...\n");
#endif

    spin_lock(&isr_request_special_lock);
    if(Device.vulpes_state == VULPES_INIT) {
        /* this value is only set by register() while dev->lock is held
         * if true, keep special_lock through return to register(), it will
         * be released there */

        ISR_DEBUG("request: INIT.\n");

        if ((req = elv_next_request(q)) != NULL) {

            ISR_DEBUG("request: cmd=%i sec=%lu nr=%lu.\n",
                    (int)req->cmd, (unsigned long)req->sector,
                    (unsigned long)req->current_nr_sectors);

            if (! blk_fs_request(req)) {
                printk (KERN_NOTICE "Skip non-CMD request\n");
                end_request(req, 0);
                return;
            }

            // XXX
            if ((!rq_data_dir(req)) && ((req->sector + req->current_nr_sectors)
                                       <= VULPES_REGBLK_SECT_PER_BUF)) {
                memcpy(req->buffer, Device.vulpes_regblk.buffer,
                       (req->current_nr_sectors * FAUXIDE_HARDSECT_SIZE));
                end_request(req, 1);
            }
            else {
                printk(KERN_WARNING "isr: bad request during init in isr_request().\n");
                end_request(req, 0);
                return;
            }
        }
        return;
    }
    spin_unlock(&isr_request_special_lock);


    //spin_lock(&Device.lock);
    if ((req = elv_next_request(q)) != NULL) {

#ifdef VERBOSE_DEBUG
        ISR_DEBUG("request: cmd=%i sec=%lu nr=%lu.\n",
                (int)req->cmd, (unsigned long)req->sector,
                (unsigned long)req->current_nr_sectors);
#endif

        if (! blk_fs_request(req)) {
            printk (KERN_NOTICE "Skip non-CMD request\n");
            end_request(req, 0);
            ////continue;
            return;
        }

        if(no_vulpes(&Device)) {
            printk(KERN_WARNING "isr: unregistered device in isr_request().\n");
            end_request(req, 0);
        }
        /* TODO: the following test is bogus.  We need to check if the process is 
           sleeping.  If more than one dev is served by the same pid, we have a
           problem. */
        else if(Device.vulpes_state == VULPES_SLEEPING) {
            int err;
            err = isr_send_vulpes_signal(&Device);
            if(err) {
                ISR_DEBUG("request: signal send failed (%d).\n", err);
                // XXX: Should we end_request here?
                end_request(req, 0);
            }
            else {
                // XXX: NB: WE DO NOT WANT TO end_request HERE OR THE CMDBLK
                // IOCTL WON'T HAVE ANYTHING TO READ
            }
        } /* If vulpes is busy, we'll catch the request when the current one completes */
    }
    //spin_unlock(&Device.lock);
}

static void isr_initialize_hw_id(struct isr_device *dev)
{
  struct hd_driveid *id;
  unsigned long totalsectors;
  unsigned long cylinders;

  id = &(dev->hw_id);

  /* Assumes that dev->vulpes_regblk.reg.volsize is valid */

  memset(id, 0, sizeof(*id));

  //totalsectors = get_capacity(Device.gd);
  totalsectors = dev->vulpes_regblk.reg.volsize;

  //cylinders = (totalsectors & ~0x3f) >> 6;
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

/* bdev argument is ignored; it's just part of the prototype provided
   by the kernel */
static int isr_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
  long totalsectors, cylinders;

  //****
  //totalsectors = fauxide_gendisk.part[MINOR(inode->i_rdev)].nr_sects;
  totalsectors = get_capacity(Device.gd);
  //cylinders = (totalsectors & ~0x3f) >> 6;
  cylinders = totalsectors / (DEFAULT_HEADS*DEFAULT_SECTORS)
    + ((totalsectors % (DEFAULT_HEADS*DEFAULT_SECTORS)) ? 1 : 0);
  if(cylinders > 1024) {
#ifdef VERBOSE_DEBUG
    printk(KERN_WARNING "isr: isr_getgeo() calculated %ld cylinders.\n", cylinders);
#endif
  }
  geo->heads = DEFAULT_HEADS;
  geo->sectors = DEFAULT_SECTORS;
  //geo->heads = 4;
  //geo->sectors = 16;
  geo->cylinders = cylinders;
  //****
  //geo->start = fauxide_gendisk.part[MINOR(inode->i_rdev)].start_sect;
  geo->start = 4;
#ifdef VERBOSE_DEBUG
  ISR_DEBUG("isr_getgeo() returning c=%u h=%u s=%u start=%lu\n", geo->cylinders, (unsigned)geo->heads, (unsigned)geo->sectors, geo->start);
#endif
  return 0;
}

static void isr_register_disk(struct isr_device *dev)
{
    ISR_DEBUG("isr_register_disk() sectors=%ld...\n",
            dev->vulpes_regblk.reg.volsize);
    dev->vulpes_state = VULPES_INIT;

//  OLD 2.4 stuff
//  register_disk(&fauxide_gendisk, 
//		MKDEV(fauxide_major, devnum*FAUXIDE_PARTS_PER_UNIT),
//		FAUXIDE_PARTS_PER_UNIT, &fauxide_bdops, 
//		(long)(dev->vulpes_regblk.reg.volsize));

    set_capacity(dev->gd, dev->vulpes_regblk.reg.volsize);
    //do_register_disk(dev, dev->vulpes_regblk.reg.volsize);

    dev->vulpes_state = VULPES_SLEEPING;
    ISR_DEBUG("  ... isr_register_disk() done.\n");

    /* special_lock was grabbed by request()  */
    if (spin_is_locked(&isr_request_special_lock))
        spin_unlock(&isr_request_special_lock);
}

/*
 * Open and close.
 */

static int isr_open(struct inode *inode, struct file *filp)
{
    int ret;

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("open:\n");
#endif

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

    //**** Not needed in 2.6 apparently [reinserted...droh]
    filp->f_flags |= O_SYNC;

    ret = set_blocksize(inode->i_bdev, VULPES_CMDBLK_BUFSIZE);
#ifdef VERBOSE_DEBUG
    ISR_DEBUG("set_blocksize returned %d\n", ret);
    ISR_DEBUG("VULP=%d, bd_block_size=%d\n",
            VULPES_CMDBLK_BUFSIZE, inode->i_bdev->bd_block_size);
#endif

    //check_disk_change(inode->i_bdev);

    return 0;
}

static int isr_release(struct inode *inode, struct file *filp)
{
#ifdef VERBOSE_DEBUG
    ISR_DEBUG("release:\n");
#endif
    return 0;
}

/*
 * Look for a media change.
 */
int isr_media_changed(struct gendisk *gd)
{
    //XXX: Do we need any of this is 2.6?
    //
    struct isr_device *dev = (struct isr_device *)gd->private_data;
    int result = dev->media_changed;

    ISR_DEBUG("media_changed: %s\n", result ? "yes" : "no");

    dev->media_changed = 0;

    return result;
}

/*
 * Revalidate.
 */
int isr_revalidate(struct gendisk *gd)
{
    struct isr_device *dev = (struct isr_device *)gd->private_data;

    ISR_DEBUG("revalidate:\n");

    set_capacity(gd, dev->vulpes_regblk.reg.volsize);

    //spin_lock(&dev->lock);
    //isr_register_disk(dev);
    //spin_unlock(&dev->lock);

    return 0;
}

/*
 * force_unregister
 */
static int
isr_force_unregister(struct isr_device *dev)
{
    pid_t tmp;
    int result = 0;

    /* LOCK dev->lock should be held before entering */

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("isr_force_unregister().\n");
#endif

    /* Indicate that the media changed */
    dev->media_changed = 1;

    /* Save current pid */
    tmp = dev->vulpes_regblk.reg.pid;

    /* Unregister the vulpes process */
    dev->vulpes_regblk.reg.pid = (pid_t)0;
    dev->vulpes_state = VULPES_NO_PID;

    /* Reset the disk capacity */
    set_capacity(dev->gd, 0);  // Until register, size=0

    /* Should sync here before letting vulpes go.  Something like...
       for(i=devnum; i<(devnum+FAUXIDE_PARTS_PER_UNIT); i++)
       fsync_dev(MKDEV(fauxide_major, i));
    */

    ISR_DEBUG("ioctl(). UNREGISTERED pid %d\n", (int)tmp);

    return result;
}

/*
 * Ioctl.
 */

static void 
isr_ioctl_register(struct isr_device *dev, void *user_ptr)
{
#ifdef VERBOSE_DEBUG
    ISR_DEBUG("ioctl(). cmd=REGISTER.");
#endif

    spin_lock(&dev->lock);
    copy_from_user(&dev->vulpes_regblk, (vulpes_regblk_t*)user_ptr, 
            sizeof(vulpes_regblk_t));

    // XXX: Old 2.4 stuff
    /* Clear old information */
    //  memset(&fauxide_blk_sizes[devnum*FAUXIDE_PARTS_PER_UNIT], 0, 
    //	 FAUXIDE_PARTS_PER_UNIT*sizeof(int));
    //  memset(&fauxide_partition_array[devnum*FAUXIDE_PARTS_PER_UNIT], 0, 
    //	 FAUXIDE_PARTS_PER_UNIT*sizeof(struct hd_struct));

    /* Fill in unit information */
    //  fauxide_blk_sizes[devnum*FAUXIDE_PARTS_PER_UNIT] =
    //    fauxide_device_array[devnum].vulpes_regblk.reg.volsize / FAUXIDE_SECTORS_PER_KB;
    //  fauxide_partition_array[devnum*FAUXIDE_PARTS_PER_UNIT].nr_sects =
    //    fauxide_device_array[devnum].vulpes_regblk.reg.volsize;

    /* Indicate that the media changed */
    dev->media_changed = 1;

    isr_initialize_hw_id(dev);

    isr_register_disk(dev);

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("ioctl(). REGISTERED pid %d\n", 
            (int)(dev->vulpes_regblk.reg.pid));
#endif

    spin_unlock(&dev->lock);
}

static int
isr_ioctl_unregister(struct isr_device *dev, void *user_ptr)
{
    vulpes_registration_t tmp;
    int result = 0;

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("ioctl(). UNREGISTER\n");
#endif

    spin_lock(&dev->lock);
    copy_from_user(&tmp, (vulpes_registration_t*)user_ptr, 
            sizeof(vulpes_registration_t));

    /* Check to see if the right process is unregistering */
    if(tmp.pid == dev->vulpes_regblk.reg.pid) {
      isr_force_unregister(dev);
    } else {
        ISR_DEBUG("ioctl(). failed to UNREGISTER pid %d. old pid=%d\n", 
                (int)tmp.pid, (int)(dev->vulpes_regblk.reg.pid));
        result = -EINVAL;
    }
    spin_unlock(&dev->lock);

    return result;
}

static void isr_process_ioctl_cmdblk(struct inode *inode, struct isr_device *dev, void *user_ptr)
{
    vulpes_cmd_head_t head;
    unsigned long flags;
    int request_status = 0xdeadbeef;
    int get_next = 0;
    int gotosleep = 0;

    // NOTE: CURRENT no longer exist
    struct request *req = elv_next_request(Queue);

    spin_lock(&dev->lock);

    copy_from_user(&head, &((vulpes_cmdblk_t*)user_ptr)->head, sizeof(vulpes_cmd_head_t));

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("process_cmdblk() cmd=%#x start=%lu num=%lu.\n", (int)head.cmd, 
              (unsigned long)head.start_sect, (unsigned long)head.num_sect);
#endif

    //****
    //spin_lock_irqsave(&io_request_lock, flags);
    spin_lock_irqsave(&dev->iolock, flags);

    /* Complete the current command */
    switch(head.cmd) {
        case VULPES_CMD_READ_DONE:
            if(head.fauxide_id == req->buffer) {
                if(head.num_sect == req->current_nr_sectors) {
                    copy_from_user(req->buffer, ((vulpes_cmdblk_t*)user_ptr)->buffer, 
                            head.num_sect*FAUXIDE_HARDSECT_SIZE);
                } else {
                    ISR_DEBUG("process_cmdblk(read_done) bad nr_sect.\n");
                }
                request_status = 1;
                get_next = 1;
            } else {
                ISR_DEBUG("process_cmdblk(read_done) id mismatch.\n");
                get_next = 1;
            }
            break;
        case VULPES_CMD_WRITE_DONE:
            if(head.fauxide_id == req->buffer) {
                request_status = 1;
                get_next = 1;
            } else {
                ISR_DEBUG("process_cmdblk(write_done) id mismatch.\n");
                get_next = 1;
            }
            break;
        case VULPES_CMD_GET:
	  /* MAK: this stanza compensates for transient network failures in
	   vulpes in the HTTP mode */
	  if(dev->media_changed == 1) {
	    check_disk_change(inode->i_bdev);
	  }
	  get_next = 1;
	  break;
        case VULPES_CMD_ERROR:
            request_status = 0;
            get_next = 1;
            break;
        default:
            /* This should probably be fatal */
            ISR_DEBUG("process_cmdblk() unknown command (%d).\n", head.cmd);
            get_next = 1;
    }

    /* End the current request */
    if(request_status == 1) {
      end_request(req, 1);
      req = NULL;
    } else if(request_status == 0) {
      /* MAK: many of these failures are due to transient network failures 
	 when in vulpes in the HTTP mode */
      /* We found that when we set the error code in end_request() to zero
	 the kernel would cache that value and continue to return the failures
	 to the calling application without retrying a call to fauxide
	 despite the fact that the network failure had cleared and we were 
	 now ready to supply data again.  Consequently, we need to trigger 
	 a cache invalidation in the kernel (IO buffer cache?).  We do that
	 by setting media_changed here.  On the next polling operation from
	 vulpes, we will note that value and call check_disk_changed(),
	 which function will indirectly cause the kernel cache to be cleared.
      */
      /* end_request(req, -EAGAIN); */
      dev->media_changed = 1;
      end_request(req, 0);

      req = NULL;
    }

    /* No need to set head.vulpes_id because it is already set */

    /* Get the next command */
    if(get_next) {
        if (!req)
            req = elv_next_request(Queue);
        if(req != NULL) {
            struct isr_device *tmp_dev;
            //****
            tmp_dev = isr_get_device_from_request(req);
            if(tmp_dev->vulpes_regblk.reg.pid == dev->vulpes_regblk.reg.pid) {
                //****
                //int minor;
                //minor = MINOR(CURRENT->rq_dev);
                head.vulpes_id = tmp_dev->vulpes_regblk.reg.vulpes_id;
                if(rq_data_dir(req)) { // WRITE
#ifdef VERBOSE_DEBUG
                    ISR_DEBUG("WRITE\n");
#endif
                    head.cmd = VULPES_CMD_WRITE;
                    //****
                    //head.start_sect = req->sector + fauxide_partition_array[minor].start_sect;
                    head.start_sect = req->sector;
                    head.num_sect = req->current_nr_sectors;
                    head.fauxide_id = req->buffer;
                    if(head.num_sect > VULPES_CMDBLK_SECT_PER_BUF) {
                        ISR_DEBUG("process_cmdblk() writing too much (%llu).\n", 
                                (unsigned long long)(head.num_sect));	    
                        head.num_sect = VULPES_CMDBLK_SECT_PER_BUF;
                    }
                    copy_to_user(((vulpes_cmdblk_t*)user_ptr)->buffer, req->buffer, 
                            head.num_sect*FAUXIDE_HARDSECT_SIZE);
                    //****
                    /* begin: ugly hack to update part table */
                    if(head.start_sect == 0) {
                        int n;
                        n = (req->current_nr_sectors > VULPES_CMDBLK_SECT_PER_BUF)
                            ? VULPES_CMDBLK_SECT_PER_BUF : req->current_nr_sectors;
                        memcpy(tmp_dev->vulpes_regblk.buffer, req->buffer, 
                                n*FAUXIDE_HARDSECT_SIZE);
                    }
                    /* end: ugly hack */
                } else if(!rq_data_dir(req)) { // READ
#ifdef VERBOSE_DEBUG
                    ISR_DEBUG("READ\n");
#endif
                    head.cmd = VULPES_CMD_READ;
                    //****
                    //head.start_sect = CURRENT->sector + fauxide_partition_array[minor].start_sect;
                    head.start_sect = req->sector;
                    head.num_sect = req->current_nr_sectors;
                    head.fauxide_id = req->buffer;
                    if(head.num_sect > VULPES_CMDBLK_SECT_PER_BUF) {
                        ISR_DEBUG("process_cmdblk() reading too much (%llu).\n", 
                                (unsigned long long)(head.num_sect));	    
                    }
                } else {
                    /* This should probably be fatal */
                    ISR_DEBUG("process_cmdblk() unknown current->command (%p).\n", 
                            req->cmd);
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

    //****
    //spin_unlock_irqrestore(&io_request_lock, flags);
    spin_unlock_irqrestore(&dev->iolock, flags);

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("   ... next cmd=%#x start=%lu num=%lu.\n", (int)head.cmd, 
              (unsigned long)head.start_sect, (unsigned long)head.num_sect);
#endif

    spin_unlock(&dev->lock);
}

int isr_ioctl (struct inode *inode, struct file *filp,
	       unsigned int cmd, unsigned long arg)
{
    int err = 0;
    int result = 0;

    struct hd_geometry geo;

#ifdef VERBOSE_DEBUG
    ISR_DEBUG("ioctl: cmd=%#x arg=%lu\n", cmd, arg);
#endif

    // XXX:  Check for device existence

    if(no_vulpes(&Device)) {
      if(cmd == FAUXIDE_IOCTL_REGBLK_REGISTER) {
	err = ! access_ok(VERIFY_READ, arg, sizeof(vulpes_regblk_t));
	if (err) return -EFAULT;
	isr_ioctl_register(&Device, (void*)arg);
	//****
	check_disk_change(inode->i_bdev);
      }
      else if(cmd == FAUXIDE_IOCTL_RESCUE) {
	ISR_DEBUG("ioctl(). cmd=RESCUE\n");
	isr_force_unregister(&Device);
	//****
	check_disk_change(inode->i_bdev);
      }
      else {
	ISR_DEBUG("ioctl() received but vulpes not registered. cmd=%#x arg=%lu\n",
		  cmd, arg);
	result = -ENOTTY;
      }
    } else {
      switch(cmd) {
      case FAUXIDE_IOCTL_CMDBLK:
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(vulpes_cmdblk_t));
	if (err) return -EFAULT;
	isr_process_ioctl_cmdblk(inode, &Device, (void*)arg);
	break;
      case FAUXIDE_IOCTL_REGBLK_UNREGISTER:
	err = ! access_ok(VERIFY_READ, arg, sizeof(vulpes_registration_t));
	if (err) return -EFAULT;
	result = isr_ioctl_unregister(&Device, (void*)arg);
        check_disk_change(inode->i_bdev);
	break;
      case FAUXIDE_IOCTL_REGBLK_REGISTER:
	err = ! access_ok(VERIFY_READ, arg, sizeof(vulpes_registration_t));
	if (err) return -EFAULT;
	spin_lock(&Device.lock);
	{
	  vulpes_registration_t tmp;
	  copy_from_user(&tmp, (vulpes_registration_t*)arg, 
			 sizeof(vulpes_registration_t));
	  ISR_DEBUG("ioctl(). failed to REGISTER pid %d. old pid=%d\n", 
		    (int)tmp.pid, (int)(Device.vulpes_regblk.reg.pid));
	  result = -EINVAL;
	}
	spin_unlock(&Device.lock);
	break;	
      case FAUXIDE_IOCTL_TEST_SIGNAL:
	spin_lock(&Device.lock);
	err = isr_send_vulpes_signal(&Device);
	spin_unlock(&Device.lock);
	if(err) {
	  ISR_DEBUG("ioctl(). TEST_SIGNAL failed %d.\n", err);
	  result = err;
	} else {
	  ISR_DEBUG("ioctl(). TEST_SIGNAL\n");
	}
	break;
      case FAUXIDE_IOCTL_RESCUE:
	ISR_DEBUG("ioctl(). cmd=RESCUE\n");
	isr_force_unregister(&Device);
	//****
	check_disk_change(inode->i_bdev);
	break;
      case HDIO_GETGEO:
	/* On kernels 2.6.16 and above, the kernel will call isr_getgeo()
	   directly and will not invoke this code. */
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(geo));
	if (err) return -EFAULT;
	err = isr_getgeo(inode->i_bdev, &geo);
	if (err) return err;
	if(copy_to_user((struct hd_geometry*)arg, &geo, sizeof(geo))) 
	  return -EFAULT;
	break;
      case HDIO_GET_IDENTITY:
	err = ! access_ok(VERIFY_WRITE, arg, sizeof(struct hd_driveid));
	if (err) return -EFAULT;
#ifdef VERBOSE_DEBUG
	ISR_DEBUG("ioctl(). HDIO_GET_IDENTITY\n");
#endif
	if(copy_to_user((struct hd_driveid*)arg, &(Device.hw_id), 
			sizeof(Device.hw_id))) 
	  return -EFAULT;
	break;
      case SCSI_IOCTL_GET_IDLUN:
	/* SCSI compatible GET_IDLUN call to get target's ID and LUN number */
	//put_user( 1,
	//		  &((Scsi_Idlun *) arg)->dev_id );
	//put_user( 1, &((Scsi_Idlun *) arg)->host_unique_id );
	return -ENOTTY;
	//scsi_cmd_ioctl(filp, Device.gd, cmd, (void __user *)arg);
	break;
      default:
	ISR_DEBUG("ioctl(). unknown cmd=%#x arg=%lu\n", cmd, arg);
	result = -ENOTTY;
      }
    }
    
    return result;
}

/*
 * The device operations structure.
 */
static struct block_device_operations isr_ops = {
    .owner           = THIS_MODULE,
    .open 	     = isr_open,
    .release 	     = isr_release,
    .media_changed   = isr_media_changed,
    .revalidate_disk = isr_revalidate,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    .getgeo	     = isr_getgeo,
#endif
    .ioctl           = isr_ioctl
};

static int __init isr_init(void)
{
    spin_lock_init(&isr_request_special_lock);

    /*
     * Set up our internal device.
     */
    spin_lock_init(&Device.lock);
    spin_lock_init(&Device.iolock);
    Device.vulpes_regblk.reg.pid = (pid_t)0;
    Device.vulpes_state = VULPES_NO_PID;
    Device.media_changed = 1;

    /*
     * Get a request queue.
     */
    Queue = blk_init_queue(isr_request, &Device.lock);
    if (Queue == NULL)
        goto out;
    blk_queue_hardsect_size(Queue, FAUXIDE_HARDSECT_SIZE);

    /*
     * Get registered.
     */
    if (register_blkdev(major_num, "isr")) {
        printk(KERN_WARNING "isr: unable to get major number\n");
        goto out;
    }

    ISR_DEBUG("init(major_num=%d).  %s [%s %s]\n", 
            major_num, Version, __DATE__, __TIME__); 

    /*
     * And the gendisk structure.
     */
    Device.gd = alloc_disk(16);
    if (!Device.gd)
        goto out_unregister;
    Device.gd->major = major_num;
    Device.gd->first_minor = 0;
    Device.gd->fops = &isr_ops;
    //Device.gd->flags |= GENHD_FL_REMOVABLE;
    Device.gd->private_data = &Device;
    strcpy (Device.gd->disk_name, "fi");
    set_capacity(Device.gd, 0);  // Until register, size=0
    Device.gd->queue = Queue;
    add_disk(Device.gd);
    
    return 0;

out_unregister:
    unregister_blkdev(major_num, "isr");
out:
    return -ENOMEM;
}

static void __exit isr_exit(void)
{
    del_gendisk(Device.gd);
    put_disk(Device.gd);
    unregister_blkdev(major_num, "isr");
    blk_cleanup_queue(Queue);
    
    ISR_DEBUG("exit(major_num=%d).\n", major_num); 
}

module_init(isr_init);
module_exit(isr_exit);
