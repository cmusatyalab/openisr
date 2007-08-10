package Server;

use POSIX;

############################################################
# Server.pm - Module for server scripts
############################################################

#########################
# Configuration variables
#########################

# Absolute path that points to the top level content directory
$CONTENT_ROOT = "/var/www/html/";

# Name server domain name
$NAMESRV = "isrserver02.isr.cmu.edu";

# List of all the content servers
@CONTENTSRVS = ("isrserver03.isr.cmu.edu", "isrserver04.isr.cmu.edu", "isrserver05.isr.cmu.edu", "isrserver06.isr.cmu.edu", "isrserver07.isr.cmu.edu", "isrserver08.isr.cmu.edu", "isrserver09.isr.cmu.edu");

# Server bin directory
$SRVBIN = "/usr/local/isr/bin";

# Maximum nonce value
$MAXNONCE = 1000000000;

# Default password
$DEFAULTPWD = 'ch@ng3m3';

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
	     get_offset
	     get_dirnum
	     get_chunknum
	     get_parcelcfg_path
	     get_numdirs
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

#
# get_offset converts a directory number and chunk number to a keyring offset
#
sub get_offset {
    my $dirnum = shift;
    my $chunknum = shift;
    my $chunksperdir = shift;
    return ($dirnum * $chunksperdir) + $chunknum;
}

#
# get_dirnum - converts a keyring offset to a directory number
#
sub get_dirnum {
    my $offset = shift;
    my $chunksperdir = shift;
    return int($offset / $chunksperdir);
}

#
# get_chunknum - converts a keyring offset to a chunk number
#
sub get_chunknum {
    my $offset = shift;
    my $chunksperdir = shift;
    return $offset % $chunksperdir;
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

# Every module must end with a 1; 
1;
