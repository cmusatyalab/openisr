#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

extern char *svn_branch;
extern char *svn_revision;

#define log(prio, msg, args...) printk(prio "dm-convergent: " msg, ## args)
#define debug(msg, args...) log(KERN_DEBUG, msg, args)

/* argument format: blocksize backdev backdevoffset */
/* XXX how does backdevoffset work if our own starting offset is nonzero? */
static int convergent_target_ctr(struct dm_target *target,
				unsigned int argc, char **argv)
{
	char *endp;
	unsigned blocksize;
	unsigned offset;

	if (argc != 3) {
		target->error="convergent: invalid arguments: should be " \
				"<blocksize> <backing-device> " \
				"<backing-device-offset>";
		return -EINVAL;
	}

	blocksize=simple_strtoul(argv[0], &endp, 10);
	/* XXX hardsect_size maximum is 65536! */
	if (*endp != 0 || blocksize % 512 != 0 ||
				blocksize > (unsigned short)-1) {
		target->error="convergent: block size must be multiple of 512 and <= 65536";
		return -EINVAL;
	}
	target->limits.hardsect_size=blocksize;
	
	/* XXX offset could be long long */
	offset=simple_strtoul(argv[2], &endp, 10);
	if (*endp != 0) {
		target->error="convergent: invalid backing device offset";
		return -EINVAL;
	}
	debug("blocksize %u, backdev %s, offset %u\n", blocksize, argv[1], offset);
	
	/* XXX variable offset size depending on large device support */
//	dm_get_device(target, argv[1], offset, 
	return -EINVAL;
}

static void convergent_target_dtr(struct dm_target *target)
{
	
}

static int convergent_map(struct dm_target *target, struct bio *bio,
				union map_info *map_context)
{
	return -EINVAL;
}

static struct target_type convergent_target = {
	.name =		"convergent",
	.version =	{0,0,0}, /* XXX */
	.ctr =		convergent_target_ctr,
	.dtr =		convergent_target_dtr,
	.map =		convergent_map
};

static int __init convergent_init(void)
{
	int ret;
	printk(KERN_INFO "dm-convergent: starting (%s, rev %s)\n",
			svn_branch, svn_revision);
	ret=dm_register_target(&convergent_target);
	if (ret)
		log(KERN_ERR, "convergent registration failed: %d", ret);
	return ret;
}

static void __exit convergent_shutdown(void)
{
	int ret;
	ret=dm_unregister_target(&convergent_target);
	if (ret)
		log(KERN_ERR, "convergent unregistration failed: %d", ret);
}

module_init(convergent_init);
module_exit(convergent_shutdown);
#if 0
/* XXX */
MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION(DM_NAME " target for convergent encryption and compression");
MODULE_LICENSE();
#endif

