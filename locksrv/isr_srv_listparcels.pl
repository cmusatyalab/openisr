#!/usr/bin/perl

###################################################################
# isr_srv_listparcels.pl - List the parcels available to a user
###################################################################

#
#                       Internet Suspend/Resume
#           A system for capture and transport of PC state
#
#              Copyright (c) 2002-2004, Intel Corporation
#            Copyright (c) 2004, Carnegie Mellon University
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
use Getopt::Std;
use File::Basename;
use Sys::Hostname;
use lib "/usr/local/isr/bin";
use Server;
$| = 1; # Autoflush output on every print statement

####################
# Begin main routine
####################
my $homedir;
my $verbose;
my $username;
my $file;
my $isrdir;
my @files;
my @dirs;

#
# Parse the command line args
#
no strict 'vars';
getopts('hVu:');

if ($opt_h) {
    usage();
}
if (!$opt_u) {
    usage("Missing user name (-u)");
}
$username = $opt_u;
$verbose = $opt_V;
use strict 'vars';

#
# Set some variables that we'll need later
#
$homedir = $ENV{HOME};
if ($username ne basename($homedir)) {
    errexit("The user name on the command line ($username) is inconsistent with the home directory ($homedir).");
}
$isrdir = "$homedir/.isr/";

#
# Return the list of parcel directories via stdout
#
opendir(DIR, $isrdir)
    or unix_errexit("Could not open directory $isrdir");
@files = sort grep(!/^[\.]/, readdir(DIR));  # filter out any dot files
closedir(DIR);

@dirs = ();
foreach $file (@files) {
    # A parcel dir is a directory that contains a parcel.cfg file
    if (-d "$isrdir/$file" and -e "$isrdir/$file/parcel.cfg") {
	print "$file\n";
    }
}

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

    print "Usage: $progname [-h] -u <user>\n";
    print "Options:\n";
    print "  -h    Print this message\n";
    print "  -u    User name\n";    
    print "\n";
    exit 0;
}


