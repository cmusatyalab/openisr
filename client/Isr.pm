package Isr;

##############################################################
# Isr.pm - Module that exports system-level config info to 
#          ISR clients
#
# $Id$
##############################################################

# Locations of relevant directories
$ISRSERVERBIN = "/usr/local/isr/bin";
$LIBDIR = "/usr/lib/openisr";
$SHAREDIR = "/usr/share/openisr";
$SYSCONFDIR = "/etc/openisr";

# Client session log filename
$LOGFILE = "session.log";

# Existence of this file is a flag indicating that the temporary
# dirty cache is consistent with the local cache.
$CONSISTENT_DIRTYCACHE_FILE = "consistent-dirtycache-flag";

# Return codes for storage module functions
$ESUCCESS  = 0;  # Success
$ENOSPACE  = 1;  # Not enough space
$ENOTSUPP  = 2;  # Operation not supported
$ETIMEDOUT = 3;  # Network/server failure partway through
$EINVAL    = 4;  # Misc error

# Every module must end with a 1; 
1;
