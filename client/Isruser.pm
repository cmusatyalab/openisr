package Isr;

##############################################################
# Isruser.pm - Module that exports user-level config info 
#              to ISR clients
#
# $Id: Isruser.pm,v 1.5 2005/09/16 18:20:43 mtoups Exp $
##############################################################

# Default userid (override with -u)
# If this variable is "", then it defaults to the Unix login name
$USERID = "";

# Every module must end with a 1; 
1;
