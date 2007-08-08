/*
 * Parcelkeeper - support daemon for the OpenISR (TM) system virtual disk
 *
 * Copyright (C) 2006-2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include "defs.h"

struct pk_config config = {
	.log_info_str = "",
	.log_stderr_mask = -1,
	.compress = COMP_NONE
};
struct pk_state state;

/* XXX lockfile */
int main(int argc, char **argv)
{
	int ret=1;
	int have_cache=0;
	int have_transport=0;
	int have_nexus=0;

	parse_cmdline(argc, argv);
	log_start();
	if (parse_parcel_cfg())
		goto shutdown;

	if (cache_init())
		goto shutdown;
	else
		have_cache=1;

	if (transport_init())
		goto shutdown;
	else
		have_transport=1;

	if (nexus_init())
		goto shutdown;
	else
		have_nexus=1;

	ret=0;
	nexus_run();

shutdown:
	if (have_nexus)
		nexus_shutdown();
	if (have_transport)
		transport_shutdown();
	if (have_cache)
		cache_shutdown();
	log_shutdown();
	return ret;
}
