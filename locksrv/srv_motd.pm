###################################################################
# srv_motd.pm - Return the message of the day on stdout
###################################################################

#
#                     Internet Suspend/Resume (R)
#           A system for capture and transport of PC state
#
#              Copyright (c) 2002-2004, Intel Corporation
#         Copyright (c) 2004-2007, Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

###################
# Standard prologue
###################
use strict;

####################
# Begin main routine
####################
my $parcelname;
my $username;
my $motdfile;

#
# Parse the command line args
#
no strict 'vars';
getopts('hu:p:');

if ($opt_h) {
    usage();
}

if (!$opt_p) {
    usage("Missing parcel name (-p)");
}
if (!$opt_u) {
    usage("Missing user name (-u)");
}
$parcelname = $opt_p;
$username = $opt_u;
use strict 'vars';

#
# Set some variables that we'll need later
#
$motdfile = "/etc/openisr/motd";

#
# Return the config file to the caller via stdout
#
open(INFILE, $motdfile) 
    or exit 0;
print "\nServer message:\n";
while (<INFILE>) {
    print $_;
}
close (INFILE) 
    or unix_errexit("Unable to close $motdfile.");
print "\n";

exit 0;

##################
# End main routine
##################

#
# usage - print help message and terminate
#
sub usage
{
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    if ($msg) {
        print "$progname: $msg\n";
    }

    print "Usage: $progname [-h] -p <parcel> -u <user>\n";
    print "Options:\n";
    print "  -h    Print this message\n";
    print "  -p    Parcel name\n";    
    print "  -u    User name\n";    
    print "\n";
    exit 0;
}
