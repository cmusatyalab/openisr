#######################################################################
# HTTPSSH.pm - Distributed storage system module (HTTP/SSH version)
#######################################################################

#
# isr - Client user interface for the Internet Suspend/Resume (R) system
#
# Copyright (C) 2004-2007 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

#####################
# Section 0: Prologue
#####################
use File::Path;
use File::Copy;
use IO::Socket;
use Isr;
use strict;
use warnings;
use Term::ANSIColor qw(:constants);
use vars qw(%syscfg %cfg);

#############################
# Section 1: Public functions
#############################

#
# isr_sget - Copy a file from remote store to local store.  The client will
#            ignore SIGINT/SIGQUIT while the transfer is in progress;
#            $Isr::EINTR will be returned if one of these was received by
#            the child process.
#
sub isr_sget ($$$$) {
    my $userid = shift;    # ISR userid
    my $frompath = shift;  # protocol-independent server "from" suffix 
    my $topath = shift;    # local "to" path name
    my $progmeter = shift; # print a progress meter

    my $i;
    my $retval;
    my $flag;
    
    $flag = "-sS";    
    if ($progmeter and $main::verbose) {
	$flag = "";
    }
	
    # Retry if the get operation fails
    for ($i = 0; $i < $syscfg{retries}; $i++) {
	$retval = system("curl --connect-timeout $syscfg{connect_timeout} $flag -f -G $main::cfg{RPATH}/$frompath > $topath");
	if ($retval == 0) {
	    return ($Isr::ESUCCESS);
	}
	if (WIFSIGNALED($retval)) {
	    # curl process killed by signal.  Don't retry.
	    return $Isr::EINTR;
	}
	print "[isr] get operation failed. Retrying...\n"
	    if $main::verbose;
	sleep(1);
    }
    return ($retval);
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
    my $command = "isr_srv_" . $operation . ".pl"; 
    my $redirect = "";

    # Redirect stderr to outfile if requested
    if ($stderr) {
	$redirect = "2>&1";
    }

    # Perform the operation on remote storage
    if ($outfile) {
	$retval = mysystem("ssh -l $userid $main::server $Isr::ISRSERVERBIN/$command $args > $outfile $redirect");
    }
    else {
	$retval = mysystem("ssh -l $userid $main::server $Isr::ISRSERVERBIN/$command $args");
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
# isr_connected_http - Return true if client can talk to remote store
#
sub isr_connected_http () {

    if (IO::Socket::INET->new(PeerAddr => "$main::server",
			      PeerPort => "80",
			      Proto    => "tcp",
			      Type     => SOCK_STREAM)) {
	return 1;
    }
    else {
	return 0;
    }
}

#
# isr_run_parcelkeeper - Run the Parcelkeeper process and return its
#                        exit status.
#
sub isr_run_parcelkeeper ($$$) {
    my $userid = shift;        # ISR user id
    my $parceldir = shift;     # local parcel directory
    my $disconnected = shift;  # Are we running disconnected?

    my $logstring = "|PARCELKEEPER|" . message_string() ."|";
    my $cachedir = "$parceldir/cache";
    my $pkcmd = "$Isr::LIBDIR/parcelkeeper";

    my $hoarddir = "$parceldir-hoard";
    my $hoardopt = "";
    
    my $retval;

    # Check for existence of the hoard directory and set the PK hoard flag
    if (-d $hoarddir) {
        $hoardopt = "--hoard $hoarddir";
        print("\tUsing hoard $hoarddir.\n")
	    if $main::verbose > 1;
    }

    #
    # Crank up PK with all the right arguments
    #
    $retval = system("$pkcmd run --parcel $parceldir --cache $cachedir --master $main::cfg{RPATH}/last/hdk --compression $main::syscfg{compression} --log $parceldir/../$main::parcel.log '$logstring' $syscfg{logmask} $syscfg{console_logmask} $hoardopt");

    return $retval;
}

#
# isr_hoard - Block until the parcel is cached locally
# 
sub isr_hoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";

    #
    # If we don't have a local keyring on this host, then retrieve
    # it from the server into a temporary 'last' directory
    #
    if (!-e "$lastdir/keyring") {

	# Assign a temporary 'last' directory and clean any existing
	# temp files for this user and parcel
	$lastdir = "$isrdir/tmplast-$userid-$parcel-$$";
	mysystem("rm -rf $isrdir/tmplast-$userid-$parcel*");

	# Before going any further, make sure we have a protocol level
	# connection to the server and a valid parcel
	if (!isr_connected_http()) {
	    errexit("The server appears to be down.");
	}
	if (!isr_connected_parcel($userid, $parcel)) {
	    errexit("Remote parcel $userid/$parcel not found on the server.");
	}

	# Fetch the encrypted keyring into the last dir
	print("Fetching keyring from the server.\n")
	    if $main::verbose;
	mktree($lastdir)
	    or errexit("Unable to make $lastdir");
	unlink("$lastdir/tmpfile");
	if (isr_sget($userid, "last/keyring.enc", "$lastdir/tmpfile", 0) != $Isr::ESUCCESS) {
	    mysystem("rm -rf $lastdir");
	    errexit("Unable to fetch keyring.enc");
	}
	if (!rename("$lastdir/tmpfile", "$lastdir/keyring.enc")) {
	    mysystem("rm -rf $lastdir");
	    unix_errexit("Unable to commit $lastdir/keyring.enc");
	}

	# Save the keyroot in the parcel directory (otherwise we would
	# need to include the actual keyroot on the command line)
	if (open(KEYROOT, ">$lastdir/keyroot") == 0) { 
	    mysystem("rm -rf $lastdir");
	    unix_errexit("Unable to open $lastdir/keyroot for writing");
	}
	print KEYROOT "$main::cfg{KEYROOT}";
	close(KEYROOT);

	# Decrypt the keyring
	if (mysystem("openssl enc -d -aes-128-cbc -in $lastdir/keyring.enc -out $lastdir/keyring -pass file:$lastdir/keyroot -salt") != 0) {
	    mysystem("rm -rf $lastdir");
	    errexit("Unable to decrypt keyring.enc");
	}
	unlink("$lastdir/keyring.enc");

	# Keyroot no longer needed, get rid of it
	unlink("$lastdir/keyroot");
    }

    # 
    # Fetch any chunks that are missing from the hoard cache from the server
    #
    print("Hoarding any missing disk blocks from the server...\n")
	if $main::verbose;
    
    # XXX

    # Fetch the chunk into a temporary file in the hoard cache. If
    # the sget fails after its retries, return an error code to the
    # caller so that it can retry the entire hoard operation. 
    # IMPORTANT: this higher level retry allows us to run hoard 
    # concurrent with checkin operations. During a commit on the
    # server from version k to k+1, most chunks are removed from
    # version k into k+1. When this happens during an sget, the
    # requested chunk no longer exists, so we need to rerun the 
    # hoard operation.
    
    return $Isr::ESUCCESS;
}

#
# isr_stathoard - Report the number of chunks in the hoard cache
# 
sub isr_stathoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $numchunks = 0;
    
    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $hoarddir = "$isrdir/$parcel-hoard";

    #
    # Simple case where nothing is hoarded
    #    
    if(!-d "$hoarddir") {
	return 0;
    }
    
    # XXX
    
    return $numchunks;
}

#
# isr_sync - Make local state clean
#
sub isr_sync ($$$$) {
    my $userid = shift;     # login name
    my $parcel = shift;     # parcel name
    my $isrdir = shift;     # absolute path of local ISR home dir
    my $releasing = shift;  # whether we're releasing the lock afterward

    # Garbage collect the hoard cache
    isr_priv_cleanhoard($userid, $parcel, $isrdir);

    # Upload the dirty blocks in a cache directory on the server
    isr_priv_upload($userid, $parcel, $isrdir) == $Isr::ESUCCESS
	or errexit("Upload of parcel $userid/$parcel failed.");

    # Operations from this point on should not be interrupted by the user
    block_sigint();

    # Commit the dirty blocks to a new version
    isr_priv_commit($userid, $parcel, $isrdir, $releasing) == $Isr::ESUCCESS
	or errexit("Commit of parcel $userid/$parcel failed.");

    # If $releasing == 1, it is not safe to unblock SIGINT until the parceldir
    # is removed by our caller, since the last/ dir is not up-to-date.

    return $Isr::ESUCCESS;
}

#
# isr_statparcel - Report general statistics about a local parcel
#
sub isr_statparcel ($$$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;
    my $checkcache = shift;  # 1->check all 2->local cache 3->hoard cache

    my $memsize;

    my @files = ();

    my $parceldir = "$isrdir/$parcel";
    my $cachedir = "$parceldir/cache";
    my $lastdir = "$parceldir/last";
    
    #
    # Display the size of the memory image (if it exists)
    #
    if (-e "$cachedir/cfg") {
	opendir(DIR, "$cachedir/cfg") 
	    or unix_errexit("Unable to open $cachedir/cfg.");
	@files = grep(/\.vmem$/, readdir(DIR));
	closedir(DIR);
	if (@files > 0) {
	    $memsize = (stat("$cachedir/cfg/$files[0]")->size)/(1<<20);
	    printf("Memory image: %d MB (uncompressed)\n", $memsize);
	}
    }

    #
    # Display local cache stats
    #
    if (-e "$cachedir") {
	mysystem("$Isr::LIBDIR/parcelkeeper examine --parcel $parceldir --cache $cachedir --last $lastdir --log /dev/null ':' 0x0 $syscfg{console_logmask}") == 0
	    or errexit("Could not examine cache");
    }
    
    #
    # Verify that each block in local cache has a valid keyring tag, if
    # requested
    #
    if ($checkcache == 1 or $checkcache == 2) {
	mysystem("$Isr::LIBDIR/parcelkeeper validate --parcel $parceldir --cache $cachedir --last $lastdir --log /dev/null ':' 0x0 $syscfg{console_logmask}") == 0
	    or errexit("Could not validate cache");
    }

    #
    # Display stats about the hoard cache and check for consistency (optional)
    #
    if ($checkcache == 1 or $checkcache == 3) {
	isr_checkhoard($userid, $parcel, $isrdir, 1, 1);
    }
    else {
	isr_checkhoard($userid, $parcel, $isrdir, 0, 1);
    }
}


#
# isr_checkhoard - Reports on the consistency of the hoard cache
# 
sub isr_checkhoard ($$$$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;
    my $checkstate = shift;
    my $printstats = shift;

    my $trashcnt = 0;
    my $size_hoarded;
    my $num_hoarded;
    my $percent_hoarded;
    my $max_mbytes;

    my $parceldir = "$isrdir/$parcel";
    my $cachedir = "$parceldir/cache";
    my $lastdir = "$parceldir/last";
    my $hoarddir = "$isrdir/$parcel-hoard";

    #
    # A nonexistent hoard cache is consistent by default
    #
    if (!-e $hoarddir) {
	return $Isr::SUCCESS;
    }
    
    # XXX
    
    #
    # Display some statistics about the hoard cache
    #
    $max_mbytes = int(($cfg{NUMCHUNKS}*$cfg{CHUNKSIZE})/(1<<20));
    $num_hoarded = isr_stathoard($userid, $parcel, $isrdir);
    $size_hoarded = int(($num_hoarded*$cfg{CHUNKSIZE})/(1<<20));
    $percent_hoarded = ($size_hoarded/$max_mbytes)*100;
    if ($printstats) {
	printf("Hoard cache : %d%% populated (%d/%d MB), %d unused chunks\n",
	       $percent_hoarded, $size_hoarded, $max_mbytes, $trashcnt);
	print("$num_hoarded/$cfg{NUMCHUNKS} non-garbage blocks are hoarded.\n")
	    if $main::verbose > 1;
    }


    #
    # Optionally check the subset of hoarded files that are in the keyring
    # for consistency.
    #
    if ($checkstate) {
	print "Checking hoard cache for internal consistency...\n"
	    if $main::verbose;
	# XXX
    }

    #
    # If we get this far, everything is OK
    #
    return $Isr::SUCCESS;
}

#####################################
# Section 2: Private helper functions
#####################################

#
# isr_priv_upload - Upload a copy of the parcel to temp cache on the server.
#          Note: Upload is idempotent. You can run it over and over again 
#          until it works.
#
sub isr_priv_upload ($$$) {
    my $userid = shift;     # login name
    my $parcel = shift;     # parcel name
    my $isrdir = shift;     # absolute path of local ISR home dir

    my $dirtybytes = 0;
    my $dirtyblocks = 0;
    my $virtualbytes;
    my $vflag = "-q";
    my $bwflag = "";
    my $i;

    my $parceldir = "$isrdir/$parcel";
    my $hoarddir = "$isrdir/$parcel-hoard";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $tmpdir = "$parceldir/tmp";
    my $cdcache_file = "$parceldir/$Isr::CONSISTENT_DIRTYCACHE_FILE";

    #
    # Check to see if there is anything to upload
    #
    if (!-e $cachedir) {
	print "Local cache is empty. Nothing to upload.\n"
	    if $main::verbose;
	return $Isr::ESUCCESS;
    }

    #
    # Before going any further, make sure we have a protocol level 
    # connection to the server and a consistent parcel
    # 
    if (!isr_connected_http()) {
	errexit("The server appears to be down.");
    }
    if (!isr_connected_parcel($userid, $parcel)) {
	errexit("The remote parcel $userid/$parcel is not available.");
    }

    #
    # We expect either all or none of the cache files
    #
    
    # XXX
    if (-e "$cachedir/keyring" and 
	-e "$cachedir/cfg") {
	# OK
    }
    else {
	if (-e "$cachedir/keyring" or 
	    -e "$cachedir/cfg") {
	    errexit("Inconsistent cache directory $cachedir");
	}
    }

    #
    # Copy the dirty parcel state to a temporary dirty cache
    # directory.  When the operation is finished, create a consistent
    # dirty cache flag on disk that tells us that the dirty cache is
    # consistent with the local cache, and thus the copy operation can
    # be skipped if the subsequent upload operation is
    # interrupted. This is an optimization that eliminates unnecessary
    # compress and encrypt operations, and better exploits the features
    # of rsync if the upload is interrupted and has to be restarted
    # (mainly because tar is not idempotent).
    #
    if (!-e $cdcache_file) {
	($dirtybytes, $dirtyblocks) = 
	    copy_dirtychunks($parceldir);
	open(FLAG, ">$cdcache_file")
	    or unix_errexit("Unable to create dirty cache flag ($cdcache_file)");
	close FLAG;
    }
    else {
	print("Skipping local copy operation.\n")
	    if $main::verbose;
    }

    mypause("Done with local copy, ready to upload: hit y to continue");

    # 
    # Transfer the dirty local cache state to the server
    #
    print("Sending modified disk state to server...\n")
	if $main::verbose;
    $vflag = "--progress"
        if ($main::verbose);
    $bwflag = "--bwlimit=$main::bwlimit"
	if ($main::bwlimit);

    # Retry if the upload fails
    for ($i = 0; $i < $syscfg{retries}; $i++) {
	last
	    if mysystem("rsync -e ssh --delete --partial --recursive -z $vflag $bwflag $tmpdir/cache/ $userid\@$main::cfg{WPATH}/cache") == 0;
	print "[isr] upload failed. Retrying...\n"
	    if $main::verbose;
    }
    errexit("Upload failed. Aborting.")
        if $i == $syscfg{retries};
    mypause("Done with upload, ready to commit: hit y to continue");

    #
    # Log the number of hdk bytes that were transferred
    #
    $virtualbytes = $dirtyblocks*$cfg{CHUNKSIZE};
    message("INFO", "upload:hdk:$dirtybytes:$virtualbytes");

    # We need to do this, so that if the commit doesn't finish
    # rsync doesn't blow everything away
    unlink($cdcache_file);

    # Return successful status
    print("Upload completed, all updates have been sent to the server.\n")
	if $main::verbose;

    return $Isr::ESUCCESS;
}

#
# copy_dirtychunks - Build temp cache tree and populate it with dirty state
#
sub copy_dirtychunks ($) {
    my $parceldir = shift;

    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $tmpdir = "$parceldir/tmp";
    my $tarsize = 0;
    
    my $dirtyblocks;
    my $dirtybytes;
    my $target;
    my $curfile;
    my $stat;

    #
    # Build an empty temporary cache directory structure on the client
    #
    mysystem("rm -rf $tmpdir");
    mktree("$tmpdir/cache/hdk")
	or errexit("Unable to make temporary directory $tmpdir/cache/hdk");

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
    # Figure out (roughly) how large the cfg tarball will be, so that we can
    # generate a progress bar
    #
    opendir(CFG, "$cachedir/cfg")
	or unix_errexit("Couldn't read memory image directory $cachedir/cfg");
    foreach $curfile (readdir(CFG)) {
	next if ($curfile eq "." || $curfile eq "..");
	$stat = stat("$cachedir/cfg/$curfile");
	unix_errexit("Couldn't stat $cachedir/cfg/$curfile")
	    if !$stat;
	$tarsize += $stat->size;
    }
    closedir(CFG);
    
    #
    # Create cfg tarball and encrypt it and the keyring
    #
    print("Compressing and encrypting virtual machine memory image...\n")
	if $main::verbose;
    chdir($cachedir);
    mysystem("tar c cfg | pv -peW -s $tarsize | gzip -c | openssl enc -aes-128-cbc -out $tmpdir/cache/cfg.tgz.enc -pass file:$cachedir/keyroot -salt") == 0
	or system_errexit("Unable to create cfg.tgz.enc.");
    printf("Compressed size: %d MB\n", (stat("$tmpdir/cache/cfg.tgz.enc")->size)/(1<<20))
    	if $main::verbose;
    mysystem("openssl enc -aes-128-cbc -in $cachedir/keyring -out $tmpdir/cache/keyring.enc -pass file:$cachedir/keyroot -salt") == 0
	or system_errexit("Unable to encrypt keyring.");
    foreach $target ("cfg.tgz", "keyring") {
	message("INFO", 
		sprintf("upload:$target.enc:%d:", 
			stat("$tmpdir/cache/$target.enc")->size));
    }

    # Get rid of keyroot, no longer needed
    unlink("$cachedir/keyroot"); 

    # 
    # Copy any dirty hdk chunks to the temporary cache directory
    #
    print("Collecting modified disk state...\n")
	if $main::verbose;
    mysystem("$Isr::LIBDIR/parcelkeeper upload --parcel $parceldir --cache $cachedir --last $lastdir --destdir $tmpdir/cache/hdk --log /dev/null ':' 0x0 $syscfg{console_logmask}") == 0
    	or errexit("Unable to copy chunks to temporary cache dir");
    # Hack to get stats from PK
    open(STATFILE, "$tmpdir/cache/hdk/stats");
    chomp($dirtyblocks = <STATFILE>);
    chomp($dirtybytes = <STATFILE>);
    close STATFILE;
    unlink("$tmpdir/cache/hdk/stats");

    #
    # For record keeping, the caller needs to know how many total hdk bytes
    # and total hdk blocks were transferred.
    #
    return ($dirtybytes, $dirtyblocks);
}

#
# isr_priv_commit - Commit files that were copied to server-side 
#                   cache by upload
#
sub isr_priv_commit ($$$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;
    my $releasing = shift;

    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";

    #
    # Check to see if there is anything to upload
    #
    if (!-e $cachedir) {
	print "Local cache is empty. Nothing to commit.\n"
	    if $main::verbose;
	return $Isr::ESUCCESS;
    }

    #
    # Before going any further, make sure we have a protocol level 
    # connection to the server and a consistent parcel.
    # 
    if (!isr_connected_http()) {
	errexit("The server appears to be down.");
    }
    if (!isr_connected_parcel($userid, $parcel)) {
	errexit("The remote parcel is not available.");
    }

    # If requested, check the current version of the parcel for consistency
    if (!$main::nocheckstate) {
	isr_srun($userid,"checkparcel", "-u $userid -p $parcel", "", 0) == 0
	    or errexit("There is something wrong with the remote parcel. Aborting with no change to the remote parcel.");
    }

    #
    # Trigger the server-side commit. For rsync version, do not delete
    # the server-side cache directory after the commit finishes.
    #
    if (-e $cachedir) {
        print("checking uploaded cache dir before committing...\n");
	isr_srun($userid, "checkparcel", "-s -u $userid -p $parcel", "", 0) == 0
	    or errexit("Something went wrong during upload.  Aborting with no change to the remote parcel.\n");
	print("Committing updates on server...\n")
	    if $main::verbose;
	message("INFO", "Begin server side commit");
	isr_srun($userid, "commit", "-u $userid -p $parcel", "", 0) == 0
	    or errexit("Server-side commit of parcel $userid/$parcel failed.");
	message("INFO", "End server side commit");
    }

    # If requested, check the newly committed version for consistency
    if (!$main::nocheckstate) {
	isr_srun($userid, "checkparcel", "-u $userid -p $parcel", "", 0) == 0
	     or errexit("Something went wrong during commit.  Remote parcel is inconsistent.");
    }

    #
    # If the server-side commit was successful, then do the
    # client-side commit. 
    print "Committing updates on client...\n"
	if $main::verbose;
    isr_priv_clientcommit($userid, $parcel, $isrdir, $releasing);

    return $Isr::ESUCCESS;

}

#
# isr_priv_clientcommit - Commit state on the client.  First, copy the
#     memory image and keyring from cache/ to last/, so that the
#     client-side last remains consistent with the server-side last/.
#     Second, move any dirty hdk chunks from the local cache to the hoard
#     cache so that the hoard cache stays fully populated.
#
sub isr_priv_clientcommit($$$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;
    my $releasing = shift;

    my $dirtyblocks = 0;
    my $name;
    my $sha1value;

    my $parceldir = "$isrdir/$parcel";
    my $hoarddir = "$isrdir/$parcel-hoard";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $tmpdir = "$parceldir/tmp";

    #
    # Create a hoard cache if necessary
    #
    if (!-e $hoarddir) {
	mktree($hoarddir)
	    or errexit("Unable to create $hoarddir");
    }
    
    #
    # Now that we have determined the dirty disk state, we can copy
    # the memory image and keyring from cache to last
    #
    if ($releasing) {
	# There's no point in copying the memory from cache/ to last/ if the
	# whole directory tree is going to be removed.  SIGINT is blocked, and
	# must remain blocked until the lock is released.
	message("INFO", "Client side commit - skipping copy of memory image");
    } else {
	message("INFO", "Client side commit - start copying memory image");
	opendir(DIR, "$cachedir/cfg")
	    or unix_errexit("Unable to read memory image directory $cachedir");
	foreach $name (readdir(DIR)) {
	    next if ($name eq "." || $name eq "..");
	    copy("$cachedir/cfg/$name", "$lastdir/cfg/$name")
		or unix_errexit("Unable to copy $name from $cachedir/cfg to $lastdir/cfg.");
	}
	closedir(DIR);
	copy("$cachedir/keyring", "$lastdir/keyring")
	    or unix_errexit("Unable to copy keyring from $cachedir to $lastdir.");
	message("INFO", "Client side commit - finish copying memory image");
    }

    #
    # Move any dirty cache chunks to the hoard cache
    #
    message("INFO", "Client side commit - start moving hoard chunks");
    # XXX
    message("INFO", "Client side commit - finish moving hoard chunks");
    print "Moved $dirtyblocks dirty blocks to the hoard cache.\n"
	if $main::verbose > 1;

    #
    # Move the cfg.tgz.enc and keyring.enc files into the hoard cache
    #
    $sha1value = `openssl sha1 < $tmpdir/cache/cfg.tgz.enc`;
    chomp($sha1value);
    # XXX
    # rename("$tmpdir/cache/cfg.tgz.enc", "$hoarddir/$sha1value");
    $sha1value = `openssl sha1 < $tmpdir/cache/keyring.enc`;
    chomp($sha1value);
    # XXX
    # rename("$tmpdir/cache/keyring.enc", "$hoarddir/$sha1value");
    message("INFO", "Client side commit - moved memory image into hoard cache");

    # 
    # Sync because we're paranoid
    #
    sys_sync();
    sys_sync();
    return $Isr::ESUCCESS;
}

#
# isr_priv_cleanhoard - perform garbage collection on hoard cache at sync time
# 
sub isr_priv_cleanhoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $hoarddir = "$isrdir/$parcel-hoard";

    my $deletecnt = 0;

    print "Garbage-collecting hoard cache..."
	if $main::verbose;

    #
    # Simple cases where nothing is hoarded or cached
    #    
    if ((!-e "$cachedir/keyring") || (!-d $hoarddir)) {
	print "\n"
	    if $main::verbose;
	return;
    }
    
    # XXX

    print " (Deleted $deletecnt unused chunks)\n"
	if $main::verbose;
}

# Every Perl module ends with true;
1;
