############################################################
# Server.pm - Module for server scripts
############################################################

#
#                     Internet Suspend/Resume (R)
#           A system for capture and transport of PC state
#
#              Copyright (c) 2002-2004, Intel Corporation
#         Copyright (c) 2004-2008, Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

package Server;
use POSIX;
use Sys::Hostname;
use File::Temp qw/tempfile/;
use File::Spec;

# Maximum nonce value
use constant MAXNONCE => 1000000000;

# Temporary files to be deleted at shutdown
my @tmpfiles;

###########
# Functions
###########

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(
	     err
	     errexit
	     unix_errexit
	     system_errexit
	     get_value
	     get_config
	     get_offset
	     get_parcelcfg_path
	     get_numdirs
	     keyroot_pipe
	     mktempfile
	     );

#
# err - Print an error message without exiting
#
sub err {
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    print STDERR "[$progname] Warning: $msg\n";
}

#
# errexit - print an error message and exit
#
sub errexit {
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    print STDERR "[$progname] Error: $msg\n";
    exit (1);
}

#
# unix_errexit - print an error message (with Unix strerr) and exit
#
sub unix_errexit {
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    print STDERR "[$progname] Error: $msg ($!)\n";
    exit (1);
}

#
# system_errexit - print an error after the system() function fails
#
sub system_errexit {
    my $msg = shift;
    my $exit_value = $? >> 8;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    # $? is the wait() style return value. $! is strerr[errno]
    # $exit_value  = $? >> 8;
    # $signal_num  = $? & 127;
    # $dumped_core = $? & 128;
    print STDERR "[$progname] Error: $msg [exit value=$exit_value]\n";

    # Pass the callee's exit value back to the caller
    exit $exit_value; 
}

#
# get_value - Given key, return corresponding value in a file with key=value pairs
#
sub get_value
{
    my $indexfile = shift;
    my $search_key = shift;

    my $line;
    my $line_key;
    my $line_value;
    my $return_value = -1;

    open(INFILE, $indexfile) 
	or errexit("Unable to open $indexfile");

    while ($line = <INFILE>) {
	chomp($line);
	($line_key, $line_value) = split(/[= ]+/, $line);
	if ($line_key eq $search_key) {
	    $return_value = $line_value;
	    last;
	}
    }

    close(INFILE) 
	or errexit("Unable to close $indexfile");

    if ($return_value == -1) {
	errexit("get_value unable to find key=$search_key in $indexfile.");
    }

    return $return_value;
}

sub get_config {
    my %conf = (
	# Absolute path that points to the top level content directory
	content_root => "/var/www/html",
	
	# Pathname part of HTTP base URL
	http_path => "",
	
	# Default password
	default_pass => undef,
	
	# Fully-qualified server hostname
	hostname => lc((gethostbyname(hostname()))[0]),
    );
    
    if (-r "/etc/openisr/locksrv.conf") {
	open(FD, "</etc/openisr/locksrv.conf")
	    or errexit("Couldn't load /etc/openisr/locksrv.conf");
	while (<FD>) {
	    next if /^\s*#/;
	    next if !/^\s*([a-z_]+) *= *(.*)$/;
	    if (exists $conf{$1}) {
		$conf{$1} = $2;
	    }
	}
	close(FD);
    }
    
    return %conf;
}

#
# get_offset converts a directory number and chunk number to a keyring offset
#
sub get_offset {
    my $dirnum = shift;
    my $chunknum = shift;
    my $chunksperdir = shift;
    return ($dirnum * $chunksperdir) + $chunknum;
}

sub get_parcelcfg_path {
    my $username = shift;
    my $parcel = shift;
    my $homedir = (getpwnam($username))[7];
    return "$homedir/.isr/$parcel/parcel.cfg";
}

sub get_numdirs {
    my $parcelcfg = shift;
    my $numchunks = get_value($parcelcfg, "NUMCHUNKS");
    my $chunksperdir = get_value($parcelcfg, "CHUNKSPERDIR");
    return ceil($numchunks / $chunksperdir);
}

#
# keyroot_pipe - return a handle to a pipe, and its corresponding fd, from
#                which can be read the specified string
#
sub keyroot_pipe {
    my $keyroot = shift;
    
    my $rh;
    my $wh;
    my $flags;
    
    # Each end is automatically closed when it goes out of scope
    pipe($rh, $wh)
        or unix_errexit("Couldn't create pipe");
    # Clear close-on-exec flag for the read end
    $flags = fcntl($rh, F_GETFD, 0);
    fcntl($rh, F_SETFD, $flags & ~FD_CLOEXEC);
    print $wh "$keyroot\n";
    # We can't just return fileno($rh) because $rh would drop out of scope
    return ($rh, fileno($rh));
}

#
# mktempfile - Create a unique temporary file and return its name.  The file
#              will be automatically removed at exit.
#
sub mktempfile {
    my $fh;
    my $file;
    
    # We can't use UNLINK because it doesn't run in the SIGINT path
    ($fh, $file) = tempfile("isr-XXXXXXXX", DIR => File::Spec->tmpdir())
        or errexit("Couldn't create temporary file");
    close $fh;
    # Racy, but that's OK
    push @tmpfiles, $file;
    return $file;
}

###################
# Shutdown handling
###################

sub remove_tmpfiles {
    my $file;
    
    foreach $file (@tmpfiles) {
	unlink($file);
    }
}

END {
    remove_tmpfiles();
}

$SIG{"INT"} = sub {
    remove_tmpfiles();
    $SIG{"INT"} = 'DEFAULT';
    kill("INT", $$);
};

# Every module must end with a 1; 
1;
