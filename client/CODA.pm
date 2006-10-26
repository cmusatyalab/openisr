#######################################################################
# CODA.pm - Distributed storage system module (Coda version)
#
# $Id: CODA.pm,v 1.14 2005/07/13 17:05:14 mtoups Exp $
#######################################################################

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

#####################
# Section 0: Prologue
#####################
use IO::Socket;
use lib "/usr/local/isr/bin";
use Isr;
use Isruser;
use strict;

##############################
# Section 1: Private variables
##############################

# For sanity checks, set to PROTOCOL name in parcel.cfg
my $PROTOCOL = "CODA";

#############################
# Section 2: Public functions
#############################

#
# isr_revision - Return the version number of this module
#
sub isr_revision () {
    my $unused;
    my $revision = '$Revision: 1.14 $';
    ($unused, $revision) = split(" ", $revision);
    return $revision;
}

#
# isr_checkcfg - Check key/value pairs in parcel.cfg hash
#
sub isr_checkcfg (\%) {
    my $cfg = shift;
    my %cfg = %$cfg; # dereference hash reference

    unless ($cfg{PROTOCOL} eq $PROTOCOL) {
	err("Missing or inconsistent protocol ($cfg{PROTOCOL} != $PROTOCOL) in parcel.cfg.");
	return $Isr::EINVAL;
    }
    unless ($cfg{RPATH}) {
	err("Missing RPATH entry in parcel.cfg.");
	return $Isr::EINVAL;
    }
    unless ($cfg{WPATH}) {
	err("Missing WPATH entry in parcel.cfg.");
	return $Isr::EINVAL;
    }
    unless ($cfg{KEYROOT}) {
	err("Missing KEYROOT entry in parcel.cfg.");
	return $Isr::EINVAL;
    }
    unless ($cfg{CODAPW}) {
	err("Missing CODAPW entry in parcel.cfg.");
	return $Isr::EINVAL;
    }

    # Success
    return $Isr::ESUCCESS;
}

#
# isr_make_hdk - Setup the hdk directory in the local cache
#    
sub isr_make_hdk ($$) {
    my $cachedir = shift;
    my $lastdir = shift;
    my $numdirs = shift;
    my $i;
    my $dirname;

    chdir($cachedir) == 1
	or errexit("Unable to chdir to $cachedir");
    if (! -e "hdk") {
	if(! -e "$main::cfg{WPATH}/cache/hdk") {
	    mysystem("mkdir --parents $main::cfg{WPATH}/cache/hdk") == 0
		or errexit("Unable to create $main::cfg{WPATH}/cache/hdk");
	}
	mysystem("ln -s $main::cfg{WPATH}/cache/hdk hdk") == 0
	    or errexit("Unable to create link to $main::cfg{WPATH}/cache");
	for ($i = 0; $i < $numdirs; $i++) {
	    $dirname = sprintf("%04d", $i);
	    mysystem("mkdir $cachedir/hdk/$dirname") == 0
		or system_errexit("Unable to create $cachedir/hdk/$dirname");
	}
	mysystem("cp $lastdir/hdk/index.lev1 $cachedir/hdk/index.lev1");
    }

    return $Isr::ESUCCESS;
}

#
# isr_sget - Copy a file from remote store to local store
#
sub isr_sget ($$$$) {
    my $userid = shift;    # ISR userid
    my $frompath = shift;  # protocol-independent suffix of "from" path name
    my $topath = shift;    # protocol-independent suffix of "to" path name
    my $progmeter = shift;

    return (mysystem("cp -p $main::cfg{RPATH}/$frompath $topath"));
}

#
# isr_sput - Copy a file from local store to remote store
#
sub isr_sput ($$$$$) {
    my $userid = shift;   # ISR userid
    my $frompath = shift; # protocol-independent "from" suffix
    my $topath = shift;   # protocol-independent "to" suffix
    my $progmeter = shift;
    my $compress = shift;

    return (mysystem("cp -p $frompath $main::cfg{WPATH}/$topath"));
}

#
# isr_srun - Perform an operation on parcel tree in remote store
#
sub isr_srun ($$$$$) {
    my $userid = shift;   # user name
    my $operation = shift;# requested operation
    my $args = shift;     # argument string
    my $outfile = shift;  # where to store stdout command output  (optional)
    my $stderr = shift;   # if true, redirect stderr to outfile (optional)

    my $retval;
    my $redirect = "";

    # Run the command on the client
    my $command = "$Isr::ISRSERVERBIN/isr_srv_" . $operation . ".pl"; 

    # Redirect stderr to outfile if requested
    if ($stderr) {
	$redirect = "2>&1";
    }

    # Perform the operation on remote storage
    if ($outfile) {
	$retval = mysystem("$command $args > $outfile $redirect");
    }
    else {
	$retval = mysystem("$command $args");
    }
    return $retval;
}

#
# isr_connected_parcel - Return true if parcel exists in remote store
#
sub isr_connected_parcel ($$) {
    my $userid = shift;  
    my $parcel = shift;
    
    isr_srun($userid, "ls", 
	     "-u $userid -p $parcel", "/dev/null", 1) == 0
		 or return 0;
    return 1;
}


#
# isr_connected_contentsrv - Return true if client can talk to remote store
#
sub isr_connected_contentsrv () {
    # Is there a CODA command for this?
    return 1;
}

#
# isr_run_vulpes - Run the Vulpes process. Return the vulpes 
#                  exit status.
#
sub isr_run_vulpes ($$$) {
    my $userid = shift;       # ISR user id
    my $cachedir = shift;     # local Vulpes cache directory
    my $disconnected = shift; # Are we running disconnected?

    my $retval;
    my $vulpescmd = "$Isr::ISRCLIENTBIN/vulpes";
    my $logstring = "|VULPES|" . message_string() ."|";
    my $lkaopt = "";

    $cachedir = "$cachedir/cache";

    #
    # This is a little subtle. Prefetch hdk block 0000/0000 (but only
    # if it doesn't already exist, so that Vulpes doesn't block waiting 
    # on a network access during startup.
    #
    if (!$disconnected and !-e "$cachedir/hdk/0000/0000") {
	isr_sget($userid, 
	     "last/hdk/0000/0000",  
	     "$cachedir/hdk/0000/0000", 0) == $Isr::ESUCCESS
		 or errexit("Unable to prefetch hdk/0000/0000.");
    }

    # Launch Vulpes
    # $retval = mysystem("$vulpescmd --map lev1 /dev/hdk $cachedir/hdk --keyring $cachedir/keyring --master local $main::cfg{RPATH}/last/hdk > $cachedir/vulpes.out &");
    $retval = mysystem("$vulpescmd --map lev1 /dev/hdk $cachedir/hdk --keyring $cachedir/keyring $lkaopt --master local $main::cfg{RPATH}/last/hdk --log $cachedir/../../session.log '$logstring' $Isr::LOGMASK 0x1  &");

    # Give Vulpes enough time to initialize
    mysystem("sync");
    mysystem("sleep 1");
    mysystem("sync");

    return $retval;
}

#
# isr_hoard - Block until the parcel is cached locally
# 
sub isr_hoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    print "Not implemented yet\n";
    return $Isr::ENOTSUPP;
}

#
# isr_sync - Make local state clean
#
sub isr_sync ($$$) {
    my $userid = shift;     # login name
    my $parcel = shift;     # parcel name
    my $isrdir = shift;     # absolute path of local ISR home dir

    my $numfiles;
    my $target;
    my $i;
    my $dirtyblocks;
    my $line1;
    my $line2;
    my $entry;
    my $chunkdir;
    my $chunkfile;
    my $dirname;
    my $chunksperdir;
    my $chunksize;
    my $numdirs;
    my $maxbytes;
    my $maxmbytes;
    my $bytes_transferred;
    my $virtual_bytes;
    my $tmpdir;
    my $clientname = hostname();
    my $numchunks;
    my $chunk;
    my $tag;
    my $chunkname;

    my @keyring;
    my @chunkdiffs;
    my @files;

    my $parceldir = "$isrdir/$parcel";
    my $hoarddir = "$isrdir/$parcel-hoard";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $sha1value;

############## UPLOAD

    #
    # Check to see if there is anything to upload
    #
    if (!-e $cachedir) {
	print "Local cache is empty. Nothing to upload.\n"
	    if $main::verbose;
	return;
    }

    #
    # Before going any further, make sure we have a protocol level 
    # connection to the content server and a consistent parcel
    # 
    if (!isr_connected_contentsrv()) {
	errexit("The content server appears to be down.");
    }
    if (!isr_connected_parcel($userid, $parcel)) {
	errexit("The remote parcel is not available.");
    }

    #
    # We expect either all or none of the cache subdirectories
    #
    if (-e "$cachedir/keyring" and -e "$cachedir/cfg" and -e "$cachedir/hdk") {
	# OK
    }
    else {
	if (-e "$cachedir/keyring" or -e "$cachedir/cfg" or -e "$cachedir/hdk") {
	    errexit("Dirty state mismatch in $cachedir");
	}
    }

    #
    # Save a copy of the keyroot in the cache (otherwise we would
    # need to include the actual keyroot on the command line, which
    # would not be secure)
    #
    open(KEYROOT, ">$cachedir/keyroot") 
	or errexit("Unable to open $cachedir/keyroot for writing");
    print KEYROOT "$main::cfg{KEYROOT}";
    close(KEYROOT);

    #
    # Create the cfg tarball
    #
    print("Compressing and encrypting virtual machine memory image...\n")
	if $main::verbose;
    chdir($cachedir);
    mysystem("tar czf cfg.tgz cfg") == 0
	or system_errexit("Unable to create cfg.tgz.");

    #
    # Encrypt the cfg tarball and keyring using the keyroot 
    #
    print("Encrypting virtual machine memory image...\n")
	if $main::verbose > 1;
    foreach $target ("cfg.tgz", "keyring") {
	mysystem("openssl enc -bf -in $cachedir/$target -out $cachedir/$target.enc -pass file:$cachedir/keyroot -nosalt") == 0
	    or system_errexit("Unable to encode $cachedir/$target.");
    }

    # Get rid of keyroot, no longer needed
    unlink("$cachedir/keyroot"); 

    #
    # Send the encrypted keyring, cfg, and index.lev1 files to the
    # cache directory on the content server.
    #
    printf("Sending virtual machine memory image (%.1f MB) to content server...\n", int(stat("$cachedir/cfg.tgz.enc")->size/(1<<20)))
	if $main::verbose;

    foreach $target ("keyring.enc", "cfg.tgz.enc") {
	printf("Sending $target (%.1f MB)\n", 
	       int(stat("$cachedir/$target")->size/(1<<20)))
	    if $main::verbose > 1;
	isr_sput($userid, 
		 "$cachedir/$target", 
		 "cache/$target", 1, 0) == $Isr::ESUCCESS
		     or errexit("Unable to send $target to content server.");
	message("INFO", 
		sprintf("upload:$target:%d:", 
			stat("$cachedir/$target")->size));
    }

########## COMMIT

    #
    # Trigger the server-side commit
    #
    if (-e $cachedir) {
	print("Committing updates on content server...\n")
	    if $main::verbose;
	isr_srun($userid, "commit", "-p $userid/$parcel", "", 0) == 0
	    or errexit("Server-side commit of parcel $parcel failed.");
    }

    #
    # CODA HACK: recreate the serverside cache/hdk dirs 
    #
    mysystem("mkdir --parents $main::cfg{WPATH}/cache/hdk") == 0
	or errexit("Unable to recreate serverside cache/hdk.");

    #
    # If the server-side commit was successful, then do the
    # client-side commit by copying files from from cachedir back to
    # lastdir. The main idea here is that client-side lastdir must be
    # consistent with server-side lastdir.
    #
    print "Committing updates on client...\n"
	if $main::verbose;
    mysystem("cp -f $cachedir/cfg/* $lastdir/cfg") == 0
	or system_errexit("Unable to copy memory image from $cachedir to $lastdir/cfg.");
    mysystem("cp -f $cachedir/keyring $lastdir") == 0
	or system_errexit("Unable to copy keyring from $cachedir to $lastdir.");

    return $Isr::ESUCCESS;

}

#
# isr_statparcel - Report general statistics about a local parcel
#
sub isr_statparcel ($$$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;
    my $checkcache = shift;  # True if requesting a consistency check

    print "Not implemented yet\n";
    return $Isr::ENOTSUPP;
}


#####################################
# Section 3: Private helper functions
#####################################


# Every Perl module ends with true;
1;
