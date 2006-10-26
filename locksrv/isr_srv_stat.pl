#!/usr/bin/perl

#################################################################
# isr_srv_stat.pl - Return file metadata (from stat)
#
# $Id$
#################################################################

#
#                  Internet Suspend/Resume (Release 0.5)
#           A system for capture and transport of PC state
#
#            Copyright (c) 2004, Carnegie Mellon University
#              Copyright (c) 2002-2004, Intel Corporation
#                         All Rights Reserved
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

##########
# Prologue
##########
use strict;
use Getopt::Std;
use File::stat;
use Socket;
use Sys::Hostname;
use lib "/usr/local/isr/bin";
use Server;
use sigtrap qw(die normal-signals);
$| = 1; # Autoflush output on every print statement

####################
# begin main routine
####################

#
# Variables
#
my $filepath;
my $verbose;
my $item;
my @metadata;

#
# Parse the command line args
#
no strict 'vars';
getopts('hVf:');

if ($opt_h) {
    usage();
}
if (!$opt_f) {
    usage("Missing file path (-f)");
}
$filepath = "$Server::CONTENT_ROOT" . $opt_f;
$verbose = $opt_V;
use strict 'vars';

#
# Make sure the file exists
#
(-e $filepath)
    or errexit("$filepath does not exist.");

#
# Return the stat metadata as a list of key-value pairs
#
print "DEV=", stat($filepath)->dev, "\n";
print "INO=", stat($filepath)->ino, "\n";
print "SIZE=", stat($filepath)->size, "\n";
print "MODE=", stat($filepath)->mode, "\n";
print "NLINK=", stat($filepath)->nlink, "\n";
print "UID=", stat($filepath)->uid, "\n";
print "GID=", stat($filepath)->gid, "\n";
print "RDEV=", stat($filepath)->rdev, "\n";
print "SIZE=", stat($filepath)->size, "\n";
print "ATIME=", stat($filepath)->atime, "\n";
print "MTIME=", stat($filepath)->mtime, "\n";
print "CTIME=", stat($filepath)->ctime, "\n";
print "BLKSSIZE=", stat($filepath)->blksize, "\n";
print "BLOCKS=", stat($filepath)->blocks, "\n";
print "SHA1=", `openssl sha1 < $filepath`, "\n";
#
# Clean up and exit
#
exit 0;


##################
# end main routine
##################


#
# usage - print help message and terminate
#
sub usage {
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    if ($msg) {
        print "$progname: $msg\n";
    }

    print "Usage: $progname [-hV] -f <path>\n";
    print "Options:\n";
    print "  -h        Print this message\n";
    print "  -f <path> File path (relative to $Server::CONTENT_ROOT)\n";
    print "  -V        Be verbose\n";
    print "\n";
    exit 0;
}
