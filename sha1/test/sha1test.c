#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

static struct sha1 {
	struct mutex lock;
	struct crypto_tfm *tfm;
	struct scatterlist sg;
	void *buf;
	int users;
	int leave_open;
} sha;

static ssize_t sha_read(struct file *filp, char __user *buf,
			size_t count, loff_t *offp)
{
	u8 hash[20];
	char str[42];
	int i;
	
	if (count < 20)
		return -EINVAL;
	
	if ((unsigned long)filp->private_data)
		return 0;
	
	if (mutex_lock_interruptible(&sha.lock))
		return -ERESTARTSYS;
	
	crypto_digest_final(sha.tfm, hash);
	crypto_digest_init(sha.tfm);
	sha.leave_open=0;
	
	mutex_unlock(&sha.lock);
	
	for (i=0; i<20; i++)
		sprintf(str + 2 * i, "%.2x", hash[i]);
	sprintf(str + 2 * i, "\n");
	if (copy_to_user(buf, str, 41))
		return -EFAULT;
	filp->private_data=(void*)1;
	return 41;
}

static ssize_t sha_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *offp)
{
	int cur;
	int done=0;
	
	if (count == 0)
		return 0;
	if (mutex_lock_interruptible(&sha.lock))
		return -ERESTARTSYS;
	
	while (done < count) {
		cur=min((unsigned)(count - done), (unsigned)PAGE_SIZE);
		if (copy_from_user(sha.buf, buf + done, cur))
			break;
		sha.sg.length=cur;
		crypto_digest_update(sha.tfm, &sha.sg, 1);
		done += cur;
	}
	if (done)
		sha.leave_open=1;
	mutex_unlock(&sha.lock);
	if (done != 0) {
		filp->private_data=(void*)0;
		return done;
	} else {
		return -EFAULT;
	}
}

static int sha_open(struct inode *ino, struct file *filp)
{
	int ret=0;
	
	nonseekable_open(ino, filp);
	
	if (mutex_lock_interruptible(&sha.lock))
		return -ERESTARTSYS;
	
	if (sha.tfm == NULL) {
		sha.tfm=crypto_alloc_tfm("sha1", 0);
		if (sha.tfm == NULL) {
			ret=-ENOMEM;
			goto out;
		}
		crypto_digest_init(sha.tfm);
	}
	sha.users++;
	
out:
	mutex_unlock(&sha.lock);
	return ret;
}

static int sha_release(struct inode *ino, struct file *filp)
{
	mutex_lock(&sha.lock);
	if (!--sha.users && !sha.leave_open) {
		crypto_free_tfm(sha.tfm);
		sha.tfm=NULL;
	}
	mutex_unlock(&sha.lock);
	return 0;
}

static struct file_operations sha_ops = {
	.owner =		THIS_MODULE,
	.open =			sha_open,
	.release =		sha_release,
	.read =			sha_read,
	.write =		sha_write,
	.llseek =		no_llseek,
};

static struct miscdevice sha_miscdev = {
	.minor =		MISC_DYNAMIC_MINOR,
	.name =			"sha1test",
	.fops =			&sha_ops,
	.list =			LIST_HEAD_INIT(sha_miscdev.list),
};

int __init init(void)
{
	int ret;
	
	mutex_init(&sha.lock);
	
	sha.sg.page=alloc_page(GFP_KERNEL);
	if (sha.sg.page == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	sha.sg.offset=0;
	sha.buf=page_address(sha.sg.page);
	
	ret=misc_register(&sha_miscdev);
	if (ret)
		goto bad;
	
	return 0;
	
bad:
	if (sha.sg.page != NULL)
		__free_page(sha.sg.page);
	return ret;
}

void __exit fini(void)
{
	misc_deregister(&sha_miscdev);
	__free_page(sha.sg.page);
}

module_init(init);
module_exit(fini);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("CryptoAPI SHA-1 userspace test driver");
MODULE_LICENSE("GPL");
