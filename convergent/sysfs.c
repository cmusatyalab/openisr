#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/device.h>
#include "convergent.h"

static ssize_t drv_show_version(struct class *c, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", ISR_INTERFACE_VERSION);
}

static ssize_t drv_show_branch(struct class *c, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", svn_branch);
}

static ssize_t drv_show_revision(struct class *c, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", svn_revision);
}

struct class_attribute class_attrs[] = {
	__ATTR(version, S_IRUGO, drv_show_version, NULL),
	__ATTR(branch, S_IRUGO, drv_show_branch, NULL),
	__ATTR(revision, S_IRUGO, drv_show_revision, NULL),
	__ATTR_NULL
};



/* All of these can run before the ctr has finished! */

static ssize_t dev_show_chunksize(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->chunksize);
}

static ssize_t dev_show_cachesize(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->cachesize);
}

static ssize_t dev_show_offset(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%llu\n", (u64)dev->offset << 9);
}

static ssize_t dev_show_states(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return print_states(dev, buf, PAGE_SIZE);
}

static ssize_t dev_show_state_times(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return print_state_times(dev, buf, PAGE_SIZE);
}

static ssize_t dev_show_suite(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%s\n", get_suite_name(dev));
}

static ssize_t dev_show_compression(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%s\n",
				get_default_compression_name(dev));
}

struct class_device_attribute class_dev_attrs[] = {
	__ATTR(chunk_size, S_IRUGO, dev_show_chunksize, NULL),
	__ATTR(cache_entries, S_IRUGO, dev_show_cachesize, NULL),
	__ATTR(header_length, S_IRUGO, dev_show_offset, NULL),
	__ATTR(states, S_IRUGO, dev_show_states, NULL),
	__ATTR(state_times, S_IRUGO, dev_show_state_times, NULL),
	__ATTR(encryption, S_IRUGO, dev_show_suite, NULL),
	__ATTR(compression, S_IRUGO, dev_show_compression, NULL),
	__ATTR_NULL
};
