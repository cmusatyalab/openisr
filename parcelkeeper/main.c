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

int main(int argc, char **argv)
{
	parse_cmdline(argc, argv);
	log_start();
	transport_init();
	parse_parcel_cfg();
	transport_shutdown();
	log_shutdown();
	return 0;
}
