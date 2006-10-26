#!/usr/bin/perl

#################################################################
# isr_srv_expand.pl - Expand a tar file
#
# $Id: isr_srv_expand.pl,v 1.4 2004/11/05 18:52:39 droh Exp $
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
use Cwd;
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
my $dirpath;
my $filename;

#
# Parse the command line args
#
no strict 'vars';
getopts('hVd:f:');

if ($opt_h) {
    usage();
}
if (!$opt_f) {
    usage("Missing file name (-f)");
}
if (!$opt_d) {
    usage("Missing directory name (-d)");
}
$dirpath = "$Server::CONTENT_ROOT" . $opt_d;
$filename = $opt_f;
$verbose = $opt_V;
use strict 'vars';

#
# Make sure the file exists
#
(-e "$dirpath/$filename")
    or errexit("File $dirpath/$filename does not exist.");

#
# Expand the tarball
#
chdir($dirpath) 
    or errexit("Unable to change directory to $dirpath");
system("tar xf $filename > /dev/null 2>&1") == 0
    or errexit("Unable to expand $dirpath/$filename");

#
# Clean up and exit
#
system("rm -f $dirpath/$filename");
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
    print "  -d <path> Directory path (relative to $Server::CONTENT_ROOT)\n";
    print "  -f <name> File name (relative to $Server::CONTENT_ROOT)\n";
    print "  -V        Be verbose\n";
    print "\n";
    exit 0;
}
