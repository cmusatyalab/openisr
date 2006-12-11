#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/device.h>
#include "defs.h"

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
	int i;
	int count=0;
	
	/* XXX if we wanted to be precise about this, we should have the ctr
	   take the dev lock and then have this function lock it before
	   running */
	for (i=0; i<CD_NR_STATES; i++) {
		count += snprintf(buf+count, PAGE_SIZE-count, "%s%u",
					i ? " " : "",
					dev->stats.state_count[i]);
	}
	count += snprintf(buf+count, PAGE_SIZE-count, "\n");
	return count;
}

static ssize_t dev_show_state_times(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	int i;
	int count=0;
	unsigned time;
	unsigned samples;
	
	/* XXX poor locking discipline during setup */
	mutex_lock(&dev->lock);
	for (i=0; i<CD_NR_STATES; i++) {
		time=dev->stats.state_time_us[i];
		samples=dev->stats.state_time_samples[i];
		dev->stats.state_time_us[i]=0;
		dev->stats.state_time_samples[i]=0;
		count += snprintf(buf+count, PAGE_SIZE-count, "%s%u",
					i ? " " : "",
					samples ? time / samples : 0);
	}
	count += snprintf(buf+count, PAGE_SIZE-count, "\n");
	mutex_unlock(&dev->lock);
	return count;
}

static ssize_t dev_show_suite(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	char *str=dev->suite_name;
	if (str == NULL)
		str="unknown";
	return snprintf(buf, PAGE_SIZE, "%s\n", str);
}

static ssize_t dev_show_compression(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	char *str=dev->default_compression_name;
	if (str == NULL)
		str="unknown";
	return snprintf(buf, PAGE_SIZE, "%s\n", str);
}

static ssize_t dev_show_cache_hits(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.cache_hits);
}

static ssize_t dev_show_cache_misses(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.cache_misses);
}

static ssize_t dev_show_chunk_errors(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.chunk_errors);
}

static ssize_t dev_show_chunk_reads(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.chunk_reads);
}

static ssize_t dev_show_chunk_writes(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.chunk_writes);
}

static ssize_t dev_show_whole_writes(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.whole_chunk_updates);
}

static ssize_t dev_show_discards(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.encrypted_discards);
}

static ssize_t dev_show_sect_read(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.sectors_read);
}

static ssize_t dev_show_sect_written(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->stats.sectors_written);
}

struct class_device_attribute class_dev_attrs[] = {
	__ATTR(chunk_size, S_IRUGO, dev_show_chunksize, NULL),
	__ATTR(cache_entries, S_IRUGO, dev_show_cachesize, NULL),
	__ATTR(header_length, S_IRUGO, dev_show_offset, NULL),
	__ATTR(states, S_IRUGO, dev_show_states, NULL),
	__ATTR(state_times, S_IRUGO, dev_show_state_times, NULL),
	__ATTR(encryption, S_IRUGO, dev_show_suite, NULL),
	__ATTR(compression, S_IRUGO, dev_show_compression, NULL),
	__ATTR(cache_hits, S_IRUGO, dev_show_cache_hits, NULL),
	__ATTR(cache_misses, S_IRUGO, dev_show_cache_misses, NULL),
	__ATTR(chunk_errors, S_IRUGO, dev_show_chunk_errors, NULL),
	__ATTR(chunk_reads, S_IRUGO, dev_show_chunk_reads, NULL),
	__ATTR(chunk_writes, S_IRUGO, dev_show_chunk_writes, NULL),
	__ATTR(whole_chunk_updates, S_IRUGO, dev_show_whole_writes, NULL),
	__ATTR(chunk_encrypted_discards, S_IRUGO, dev_show_discards, NULL),
	__ATTR(sectors_read, S_IRUGO, dev_show_sect_read, NULL),
	__ATTR(sectors_written, S_IRUGO, dev_show_sect_written, NULL),
	__ATTR_NULL
};
