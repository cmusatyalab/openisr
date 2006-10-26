package Isr;

##############################################################
# Isruser.pm - Module that exports user-level config info 
#              to ISR clients
#
# $Id$
##############################################################

# Default userid (override with -u)
# If this variable is "", then it defaults to the Unix login name
$USERID = "";

# Every module must end with a 1; 
1;
