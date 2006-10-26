package Isr;

##############################################################
# Isr.pm - Module that exports system-level config info to 
#          ISR clients
#
# $Id$
##############################################################

# Default name server domain name (override with -n)
$NAMESRV = "isrserver02.isr.cmu.edu";

# What is the URL of the software server for client auto updates
# This should point to the directory that contains VERSIONS and isr_update
$UPDATEURL = "http://isr.cmu.edu/software";

# Location of bin dirs on client, content server, and name server
#$ISRBIN = "/usr/local/isr/bin";
$ISRCLIENTBIN = "/usr/local/isr/bin";
$ISRSERVERBIN = "/usr/local/isr/bin";

# VMware command (could be 'vmware' or 'vmplayer' or some other VMM)
# might have different flags for different versions
$VMCOMMAND = "vmware -q";

# Client session log filename
$LOGFILE = "session.log";

# Vulpes logging mask
$LOGMASK = "0xf";

# Host ID filename
$HOSTID = ".hostid";

# How many seconds should elapse before we decide the client is unconnected
$CONNECT_TIMEOUT = 10;

# How many seconds should elapse before we restart a failed hoard operation
$HOARD_SLEEP = 5;

# How many times to retry if a read or write request fails
$RETRIES = 5;

# By default, how many of the most recent versions should "ls -l" display
$LSVERSIONS = 5;

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
