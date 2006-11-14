#######################################################################
# HTTPSSH.pm - Distributed storage system module (HTTP/SSH version)
#
# $Id$
#######################################################################

#
#                  Internet Suspend/Resume (Release 1.1)
#           A system for capture and transport of PC state
#
#          Copyright (c) 2004-2005, Carnegie Mellon University
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
use File::Path;
use IO::Socket;
use lib "/usr/local/isr/bin";
use Isr;
use Isruser;
use strict;
use Term::ANSIColor qw(:constants);

##############################
# Section 1: Private variables
##############################

# For sanity checks, set to PROTOCOL name in parcel.cfg
my $PROTOCOL = "HTTPSSH";

#############################
# Section 2: Public functions
#############################

#
# isr_revision - Return the version number of this module
#
sub isr_revision () {
    my $unused;
    my $revision = '$Revision$'; # CVS updates this on each commit
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
    unless ($cfg{SERVER}) {
	err("Missing SERVER entry in parcel.cfg.");
	return $Isr::EINVAL;
    }

    # Success
    return $Isr::ESUCCESS;
}

#
# isr_make_hdk - Setup the hdk directory in the local cache
#    
sub isr_make_hdk ($$) {
    my $cachedir = shift; # Vulpes cache
    my $lastdir = shift;  # mirrors keyring and memory image on server

    if (!-e "$cachedir/hdk") {
	mktree("$cachedir/hdk")
	    or errexit("Unable to create $cachedir/hdk");
    }
    if (!-e "$cachedir/hdk/index.lev1") {
	mysystem("cp -p $lastdir/hdk/index.lev1 $cachedir/hdk/index.lev1") == 0
	    or system_errexit("Unable to copy $lastdir/hdk/index.lev1");
    }
    return $Isr::ESUCCESS;
}

#
# isr_sget - Copy a file from remote store to local store
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
    for ($i = 0; $i < $Isr::RETRIES; $i++) {
	$retval = mysystem("curl --connect-timeout $Isr::CONNECT_TIMEOUT $flag -f -G $main::cfg{RPATH}/$frompath > $topath");
	if ($retval == 0) {
	    return ($Isr::ESUCCESS);
	}
	print "[isr] get operation failed. Retrying...\n"
	    if $main::verbose;
	sleep(1);
    }
    return ($retval);
}

#
# isr_sput - Copy a file from local store to remote store
#
sub isr_sput ($$$$$) {
    my $userid = shift;    # ISR userid
    my $frompath = shift;  # Local "from" path
    my $topath = shift;    # Protocol-independent server "to" suffix
    my $progmeter = shift; # Display a progress meter
    my $compress = shift;  # Try to compress the data on the wire

    my $vflag;
    my $cflag;
    my $bwflag;
    my $retval;
    my $i;

    $vflag = "-q";
    if ($progmeter and $main::verbose) {
	$vflag = "--progress";
    }
	
    $cflag = "";
    if ($compress) {
	$cflag = "-z";
    }

    $bwflag = "";
    if ($main::bwlimit) {
	$bwflag = "--bwlimit=$main::bwlimit";
    }

    # Retry if the put operation fails
    for ($i = 0; $i < $Isr::RETRIES; $i++) {
	$retval =  mysystem("rsync -e ssh --partial $vflag $cflag $bwflag $frompath $userid\@$main::cfg{WPATH}/$topath");
	if ($retval == 0) {
	    return ($retval);
	}
	print "[isr] put operation failed. Retrying...\n"
	    if $main::verbose;
    }
    return ($retval);
}

#
# isr_sputdir - Copy a directory tree from local store to remote store
#
sub isr_sputdir ($$$$$) {
    my $userid = shift;    # ISR userid
    my $fromdir = shift;   # Local from directory
    my $todir = shift;     # Protocol-independent server "to" suffix
    my $progmeter = shift; # Display a progress meter
    my $compress = shift;  # Try to compress the data on the wire

    my $vflag;
    my $cflag;
    my $bwflag;
    my $retval;
    my $i;

    $vflag = "-q";
    if ($progmeter and $main::verbose) {
	$vflag = "--progress";
    }
	
    $cflag = "";
    if ($compress) {
	$cflag = "-z";
    }

    $bwflag = "";
    if ($main::bwlimit) {
	$bwflag = "--bwlimit=$main::bwlimit";
    }

    # Retry if the putdir request fails
    for ($i = 0; $i < $Isr::RETRIES; $i++) {
	$retval =  mysystem("rsync -e ssh --delete --partial --recursive $vflag $cflag $bwflag $fromdir/ $userid\@$main::cfg{WPATH}/$todir");
	if ($retval == 0) {
	    return ($retval);
	}
	print "[isr] putdir request failed. Retrying...\n"
	    if $main::verbose;
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
	$retval = mysystem("ssh -l $userid $main::cfg{SERVER} $Isr::ISRSERVERBIN/$command $args > $outfile $redirect");
    }
    else {
	$retval = mysystem("ssh -l $userid $main::cfg{SERVER} $Isr::ISRSERVERBIN/$command $args");
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

    if (IO::Socket::INET->new(PeerAddr => "$main::cfg{SERVER}",
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
# isr_run_vulpes - Run the Vulpes process. Return the vulpes 
#                  exit status.
#
sub isr_run_vulpes ($$$) {
    my $userid = shift;        # ISR user id
    my $parceldir = shift;     # local parcel directory
    my $disconnected = shift;  # Are we running disconnected?

    my $logstring = "|VULPES|" . message_string() ."|";
    my $cachedir = "$parceldir/cache";
    my $vulpescmd = "$Isr::ISRCLIENTBIN/vulpes";

    my $lkadir = "$parceldir-hoard";
    my $lkaopt = "";
    
    my $retval;

    # Check for existence of the hoard directory and set the Vulpes lka flag
    if (-d $lkadir) {
        $lkaopt = "--lka hfs-sha-1 $lkadir";
        print("\tUsing hoard $lkadir.\n")
	    if $main::verbose > 1;
    }

    #
    # Crank up Vulpes with all the right arguments
    #
    $retval = system("$vulpescmd --cache $cachedir/hdk --keyring $cachedir/keyring $cachedir/cfg/keyring.bin $lkaopt --master http $main::cfg{RPATH}/last/hdk --log $cachedir/../../session.log '$logstring' $Isr::LOGMASK $Isr::CONSOLE_LOGMASK  &");

    #
    # Give Vulpes enough time to initialize
    #
    sleep(1);

    return $retval;
}

#
# isr_hoard - Block until the parcel is cached locally
# 
sub isr_hoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $numdirs;
    my $chunksperdir;
    my $chunksize;
    my $dirname;
    my $chunkname;
    my $numchunks;
    my $chunk;
    my $maxchunks;
    my $maxbytes;
    my $key;
    my $tag;
    my $computed_tag;
    my $tmpfile;
    my $corruptfile;
    my $target;
    
    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $hoarddir = "$isrdir/$parcel-hoard";
    my @keyring;

    #
    # If we don't have a local keyring on this host, then retrieve
    # it from the content server into a temporary 'last' directory
    #
    if (!-e "$lastdir/keyring") {

	# Assign a temporary 'last' directory and clean any existing
	# temp files for this user and parcel
	$lastdir = "$isrdir/tmplast-$userid-$parcel-$$";
	mysystem("rm -rf $isrdir/tmplast-$userid-$parcel*");

	# Before going any further, make sure we have a protocol level
	# connection to the content server and a valid parcel
	if (!isr_connected_contentsrv()) {
	    errexit("The content server appears to be down.");
	}
	if (!isr_connected_parcel($userid, $parcel)) {
	    errexit("Remote parcel $userid/$parcel not found on the server.");
	}

	# Fetch the encrypted keyring into hdk index files into the last dir
	print("Fetching keyring from the content server.\n")
	    if $main::verbose;
	mktree("$lastdir/hdk")
	    or errexit("Unable to make $lastdir and $lastdir/hdk");
	foreach $target ("keyring.enc", "hdk/index.lev1") {
	    unlink("$lastdir/tmpfile");
	    print "Fetching $target...\n"
		if ($main::verbose > 1);
	    if (isr_sget($userid, "last/$target", "$lastdir/tmpfile", 0) != $Isr::ESUCCESS) {
		mysystem("rm -rf $lastdir");
		errexit("Unable to fetch $target file");
	    }
	    if (!rename("$lastdir/tmpfile", "$lastdir/$target")) {
		mysystem("rm -rf $lastdir");
		unix_errexit("Unable to commit $lastdir/$target");
	    }
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
	$target = "keyring";
	if (mysystem("openssl enc -d -bf -in $lastdir/$target.enc -out $lastdir/$target -pass file:$lastdir/keyroot -nosalt") != 0) {
	    mysystem("rm -rf $lastdir");
	    errexit("Unable to decrypt $target.enc");
	}
	unlink("$lastdir/$target.enc");

	# Keyroot no longer needed, get rid of it
	unlink("$lastdir/keyroot");
    }

    #
    # Initialize things for the hoarding process
    #
    @keyring = load_keyring("$lastdir/keyring");
    $numdirs = get_value("$lastdir/hdk/index.lev1", "NUMDIRS");
    $chunksperdir = get_value("$lastdir/hdk/index.lev1", "CHUNKSPERDIR");
    $chunksize = get_value("$lastdir/hdk/index.lev1", "CHUNKSIZE");
    $numchunks = $numdirs * $chunksperdir;
    $maxbytes = ($numdirs * $chunksperdir) * $chunksize;

    #
    # Confirm that hoarddir exists
    #
    if(!-d "$hoarddir") {
	mktree($hoarddir)
	    or errexit("Unable to create $hoarddir.");
    }
    
    # 
    # Fetch any chunks that are missing from the hoard cache from the server
    #
    print("Hoarding any missing disk blocks from the server...\n")
	if $main::verbose;

    # Iterate over each of the chunks in the keyring
    for ($chunk = 0; $chunk < $numchunks; $chunk++) {

	# get the tag of the current chunk
	$tag = $keyring[$chunk][0];
	
	# Check to see if chunk exists in hoard cache. If not fetch it.
	if (!-e "$hoarddir/$tag") {
	    $dirname = sprintf("%04d", get_dirnum($chunk, $chunksperdir));
	    $chunkname = sprintf("%04d", get_chunknum($chunk, $chunksperdir));
	    $tmpfile = "$hoarddir/tmp-hoard-$tag-$dirname-$chunkname-$$";

	    # Fetch the chunk into a temporary file in the hoard cache. If
	    # the sget fails after its retries, return an error code to the
	    # caller so that it can retry the entire hoard operation. 
	    # IMPORTANT: this higher level retry allows us to run hoard 
	    # concurrent with checkin operations. During a commit on the
	    # server from version k to k+1, most chunks are removed from
	    # version k into k+1. When this happens during an sget, the
	    # requested chunk no longer exists, so we need to rerun the 
	    # hoard operation.
	    isr_sget($userid, 
		     "last/hdk/$dirname/$chunkname",  
		     "$tmpfile", 0) == $Isr::ESUCCESS 
			 or return $Isr::ETIMEDOUT;

	    # Verify the tag and commit the temp file if everything checks out
	    $computed_tag = `openssl sha1 < $tmpfile`;
	    chomp($computed_tag);
	    if (uc($computed_tag) eq uc($tag)) {
		# Commit temp file. If anything goes wrong, return error to
		# caller and let it decide whether to restart the hoard
		# operation.
		if (!rename($tmpfile, "$hoarddir/$tag")) {
		    unix_err("[isr] Unable to move $tmpfile to $tag");
		    return $Isr::EINVAL;
		}
		sys_sync();
	    }

	    # Actual tag doesn't match expected tag. Save corrupted file 
	    # later diagnostics and return error to the caller.
	    else {
		$corruptfile = "$hoarddir/corrupt-hoard-$computed_tag-$tag-$chunk";
		err("Downloaded temp file $tmpfile is corrupted. Computed tag=$computed_tag Filename=$corruptfile.");
		rename($tmpfile, $corruptfile)
		    or unix_err("Couldn't rename $tmpfile to $corruptfile");
		return $Isr::EINVAL;
	    }
	}

	emit_hdk_progressmeter(($chunk+1)*$chunksize, $maxbytes);
    }
    reset_cursor();
    sys_sync();
    sys_sync();
    return $Isr::ESUCCESS;
}

#
# isr_stathoard - Report the number of chunks in the hoard cache
# 
sub isr_stathoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $numchunks;
    my $chunk;
    my $maxchunks;
    my $chunksperdir;
    my $dirname;
    my $chunkname;
    my $hoardfilename;
    my $tag;
    
    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $hoarddir = "$isrdir/$parcel-hoard";

    my @keyring = load_keyring("$lastdir/keyring");
    $maxchunks = scalar(@keyring);

    #
    # Simple case where nothing is hoarded
    #    
    if(!-d "$hoarddir") {
	return 0;
    }
    
    # Iterate over each of the keyring tags and count
    # the chunks that are hoarded
    $chunksperdir = get_value("$lastdir/hdk/index.lev1", "CHUNKSPERDIR");
    $numchunks = 0;
    for ($chunk = 0; $chunk < $maxchunks; $chunk++) {
	# Check to see if it exists in hoard cache
	$tag = $keyring[$chunk][0];
	$hoardfilename = "$hoarddir/$tag";
	if (-e $hoardfilename) {
	    $numchunks++;
	}
	else {
	    $dirname = sprintf("%04d", get_dirnum($chunk, $chunksperdir));
	    $chunkname = sprintf("%04d", get_chunknum($chunk, $chunksperdir));
	    print "Missing chunk $chunk ($dirname/$chunkname):$tag:) in hoard cache\n"
		if $main::verbose > 2;
	}
    }
    return $numchunks;
}

#
# isr_sync - Make local state clean
#
sub isr_sync ($$$) {
    my $userid = shift;     # login name
    my $parcel = shift;     # parcel name
    my $isrdir = shift;     # absolute path of local ISR home dir

    # Garbage collect the hoard cache
    isr_priv_cleanhoard($userid, $parcel, $isrdir);

    # Upload the dirty blocks in a cache directory on the server
    isr_priv_upload($userid, $parcel, $isrdir) == $Isr::ESUCCESS
	or errexit("Upload of parcel $userid/$parcel failed.");

    # Operations from this point on should not be interrupted by the user
    block_sigint();

    # Commit the dirty blocks to a new version
    isr_priv_commit($userid, $parcel, $isrdir) == $Isr::ESUCCESS
	or errexit("Commit of parcel $userid/$parcel failed.");

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

    my $num_chunks;
    my $max_chunks;
    my $chunksize;
    my $num_mbytes;
    my $max_mbytes;
    my $actual_percent;
    my $dirty_percent;

    my $num_dirtychunks;
    my $num_dirtymbytes;
    my $num_hoarded;
    my $size_hoarded;
    my $percent_hoarded;
    my $memsize;

    my $numkeys;
    my $tag;
    my $computed_tag;
    my $i;
    my $chunkcount;
    my $numfiles;
    my $trashcnt = 0;

    my @files = ();
    my @keyring = ();
    my %filehash = ();

    my $parceldir = "$isrdir/$parcel";
    my $cachedir = "$parceldir/cache";
    my $lastdir = "$parceldir/last";
    my $hoarddir = "$isrdir/$parcel-hoard";
    
    #
    # Display the size of the memory image (if it exists)
    #
    if (-e "$cachedir/cfg") {
	opendir(DIR, "$cachedir/cfg") 
	    or unix_errexit("Unable to open $cachedir/cfg.");
	@files = grep(/\.vmem$/, readdir(DIR));
	closedir(DIR);
	$memsize = (stat("$cachedir/cfg/$files[0]")->size)/(1<<20);
	printf("Memory image: %d MB (uncompressed)\n", $memsize);
    }

    #
    # Display local cache stats
    #
    ($num_chunks, $num_dirtychunks, $max_chunks, $chunksize) = 
	hdksize($userid, $parcel, $isrdir);

    $num_mbytes = int(($num_chunks*$chunksize)/(1<<20));
    $num_dirtymbytes = int(($num_dirtychunks*$chunksize)/(1<<20));
    $max_mbytes = int(($max_chunks*$chunksize)/(1<<20));
 
    if ($max_mbytes) {
	$actual_percent = ($num_mbytes/$max_mbytes)*100;
    } 
    else {
	$actual_percent = 0;
    }
    if ($num_mbytes) {
	$dirty_percent = ($num_dirtymbytes/$num_mbytes)*100;
    }
    else {
	$dirty_percent = 0;
    }
    printf("Local cache : %d%% populated (%d/%d MB), %d%% modified (%d/%d MB)\n", 
	    $actual_percent, $num_mbytes, $max_mbytes,
	    $dirty_percent, $num_dirtymbytes, $num_mbytes);

    printf("num_chunks=$num_chunks, num_dirtychunks=$num_dirtychunks\n")
	if $main::verbose > 1;
    
    #
    # Check the local cache for consistency (if asked)
    #
    if ($checkcache == 1 or $checkcache == 2) {
	print "Checking local cache for internal consistency...\n"
	    if $main::verbose;
	isr_priv_checkcache($userid, $parcel, $isrdir);
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

    my $numkeys;
    my $chunksize;
    my $trashcnt;
    my $numfiles;
    my $num_chunks;
    my $num_dirtychunks;
    my $chunkcount;
    my $tag;
    my $computed_tag;
    my $size_hoarded;
    my $num_hoarded;
    my $percent_hoarded;
    my $max_mbytes;
    my $max_chunks;
    my $i;

    my @files = ();
    my @keyring = ();
    my %filehash = ();

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
    
    # 
    # Get the most recent keyring
    #
    if (-e "$cachedir/keyring") {
	@keyring = load_keyring("$cachedir/keyring");
    }
    elsif (-e "$lastdir/keyring") {
	@keyring = load_keyring("$lastdir/keyring");
    }
    else {
	errexit("Unable to find keyring in cache or last");
    }
    $numkeys = scalar(@keyring);


    #
    # Determine which files in the hoard cache are in the keyring
    #
    $chunksize = get_value("$lastdir/hdk/index.lev1", "CHUNKSIZE");
    opendir(DIR, "$hoarddir")
	or errexit("Unable to open hoard cache ($hoarddir)");
    @files = grep(!/^[\._]/, readdir(DIR)); # elide . and ..
    closedir(DIR);
    
    # Initially mark each file as being garbage
    %filehash = ();
    foreach $tag (@files) {
	$filehash{$tag} = 1;
    }
    
    # Exempt each file whose tag is in the keyring from being garbage
    for ($i = 0; $i < $numkeys; $i++) {
	if ($filehash{$keyring[$i][0]}) { 
	    $filehash{$keyring[$i][0]} = 0;
	}
    }
    
    # Count the number of garbage files
    foreach $tag (keys %filehash) {
	if ($filehash{$tag}) {
	    $trashcnt++;
	}
    }	

    #
    # Display some statistics about the hoard cache
    #
    ($num_chunks, $num_dirtychunks, $max_chunks, $chunksize) = 
	hdksize($userid, $parcel, $isrdir);
    $max_mbytes = int(($max_chunks*$chunksize)/(1<<20));
    $num_hoarded = isr_stathoard($userid, $parcel, $isrdir);
    $size_hoarded = int(($num_hoarded*$chunksize)/(1<<20));
    $percent_hoarded = ($size_hoarded/$max_mbytes)*100;
    if ($printstats) {
	printf("Hoard cache : %d%% populated (%d/%d MB), %d unused chunks\n",
	       $percent_hoarded, $size_hoarded, $max_mbytes, $trashcnt);
	print("$num_hoarded/$max_chunks non-garbage blocks are hoarded.\n")
	    if $main::verbose > 1;
    }


    #
    # Optionally check the subset of hoarded files that are in the keyring
    # for consistency.
    #
    if ($checkstate) {
	print "Checking hoard cache for internal consistency...\n"
	    if $main::verbose;
	$numfiles = scalar(keys %filehash);
	$chunkcount = 0;
	foreach $tag (keys %filehash) {
	    $chunkcount++;
	    if ($filehash{$tag} == 0) {
		if (stat("$hoarddir/$tag") == 0) {
		    system_err("Unable to stat chunk $tag.");
		}
		else {
		    $computed_tag = `openssl sha1 < $hoarddir/$tag`;
		    chomp($computed_tag);
		    if ($? != 0) {
			err("Unable to compute tag ($computed_tag) for chunk $tag");
		    }
		    else {
			if (uc($computed_tag) ne $tag) {
			    system_err("Encountered a corrupt hoarded file, which we have removed. Try rerunning \"isr disconnect\" or \"isr hoard\". [Computed tag=$computed_tag hoard filename=$tag]");
			    rename("$hoarddir/$tag", "$hoarddir/corrupt-stat-$computed_tag-$tag-$chunkcount")
				or unix_err("Couldn't rename corrupt hoarded file $tag");
			}
		    }
		}
	    }
	    emit_hdk_progressmeter($chunkcount*$chunksize, 
				   $numfiles*$chunksize);
	}
	reset_cursor();
    }	

    #
    # If we get this far, everything is OK
    #
    return $Isr::SUCCESS;
}

#####################################
# Section 3: Private helper functions
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

    my $dirtybytes;
    my $dirtyblocks;
    my $virtualbytes;
    my $chunksize;
    my $sha1value;

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
	errexit("The remote parcel $userid/$parcel is not available.");
    }

    #
    # We expect either all or none of the cache subdirectories
    #
    if (-e "$cachedir/keyring" and 
	-e "$cachedir/cfg" and 
	-e "$cachedir/hdk") {
	# OK
    }
    else {
	if (-e "$cachedir/keyring" or 
	    -e "$cachedir/cfg" or 
	    -e "$cachedir/hdk") {
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
	    copy_dirtychunks($cachedir, $lastdir, $tmpdir); 
	system("touch $cdcache_file") == 0
	    or system_errexit("Unable to create dirty cache flag ($cdcache_file)");
    }
    else {
	print("Skipping local copy operation.\n")
	    if $main::verbose;
    }

    mypause("Done with local copy, ready to upload: hit y to continue");

    #
    # Reset the contents of the cache on the server. For rsync version (-r), 
    # this script simply creates the server-side cache if it doesn't exist
    #
    isr_srun($userid, "resetcache", "-p $userid/$parcel -r", "", 0) == 0
	or system_errexit("Unable to reset server-side cache.");

    # 
    # Transfer the dirty local cache state to the server
    #
    print("Sending modified disk state to content server...\n")
	if $main::verbose;
    isr_sputdir($userid, "$tmpdir/cache", "cache", 1, 1) == 0
	or errexit("Putdir operation failed. Aborting.");
    mypause("Done with upload, ready to commit: hit y to continue");

    #
    # Log the number of hdk bytes that were transferred
    #
    $chunksize = get_value("$cachedir/hdk/index.lev1", "CHUNKSIZE");
    $virtualbytes = $dirtyblocks*$chunksize;
    message("INFO", "upload:hdk:$dirtybytes:$virtualbytes");

    #
    # Move the cfg.tgz.enc and keyring.enc file into the hoard cache
    #
    if (-e $hoarddir) {
	$sha1value = `openssl sha1 < $tmpdir/cache/cfg.tgz.enc`;
	mysystem("cp -f $tmpdir/cache/cfg.tgz.enc $hoarddir/$sha1value");
	$sha1value = `openssl sha1 < $tmpdir/cache/keyring.enc`;
	mysystem("cp -f $tmpdir/cache/keyring.enc $hoarddir/$sha1value");
    }

    # We need to do this, so that if the commit doesn't finish
    # rsync doesn't blow everything away
    unlink($cdcache_file);

    #
    # Clean up the local cache directory 
    #
    unlink("$cachedir/cfg.tgz"); 

    # Return successful status
    print("Upload completed, all updates have been sent to the server.\n")
	if $main::verbose;

    return $Isr::ESUCCESS;
}

#
# copy_dirtychunks - Build temp cache tree and populate it with dirty state
#
sub copy_dirtychunks ($$$) {
    my $cachedir = shift;
    my $lastdir = shift;
    my $tmpdir = shift;

    my $dirtyblocks;
    my $dirtybytes;
    my $target;

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
    # Create cfg tarball and encrypt it and the keyring
    #
    print("Compressing virtual machine memory image...")
	if $main::verbose;
    chdir($cachedir);
    mysystem("tar czf cfg.tgz cfg") == 0
	or system_errexit("Unable to create cfg.tgz.");
    printf("%d MB\n", (stat("$cachedir/cfg.tgz")->size)/(1<<20));


    print("Encrypting virtual machine memory image...\n")
	if $main::verbose;
    foreach $target ("cfg.tgz", "keyring") {
	mysystem("openssl enc -bf -in $cachedir/$target -out $tmpdir/cache/$target.enc -pass file:$cachedir/keyroot -nosalt") == 0
	    or system_errexit("Unable to encrypt $target.");
	message("INFO", 
		sprintf("upload:$target.enc:%d:", 
			stat("$tmpdir/cache/$target.enc")->size));
    }

    # Get rid of keyroot, no longer needed
    unlink("$cachedir/keyroot"); 

    # Copy the index.lev1 file to the temporary cache directory
    mysystem("cp $cachedir/hdk/index.lev1 $tmpdir/cache/hdk/index.lev1") == 0
	or errexit("Unable to copy index.lev1.");

    # 
    # Copy any dirty hdk chunks to the temporary cache directory
    #
    print("Collecting modified disk state...\n")
	if $main::verbose;
    mysystem("$Isr::ISRCLIENTBIN/vulpes --cache $cachedir/hdk --keyring $cachedir/keyring $cachedir/cfg/keyring.bin --upload $lastdir/keyring $tmpdir/cache/hdk --log /dev/null ':' 0x0 $Isr::CONSOLE_LOGMASK") == 0
    	or errexit("Unable to copy chunks to temporary cache dir");
    # Hack to get stats from vulpes
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
sub isr_priv_commit ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";

    #
    # Check to see if there is anything to upload
    #
    if (!-e $cachedir) {
	print "Local cache is empty. Nothing to commit.\n"
	    if $main::verbose;
	return;
    }

    #
    # Before going any further, make sure we have a protocol level 
    # connection to the content server and a consistent parcel.
    # 
    if (!isr_connected_contentsrv()) {
	errexit("The content server appears to be down.");
    }
    if (!isr_connected_parcel($userid, $parcel)) {
	errexit("The remote parcel is not available.");
    }

    # If requested, check the current version of the parcel for consistency
    if (!$main::nocheckstate) {
	isr_srun($userid,"checkparcel", 
		 "-p $userid/$parcel -k $main::cfg{KEYROOT}",
		 "", 0) == 0
		 or errexit("There is something wrong with the remote parcel. Aborting with no change to the remote parcel.");
    }

    #
    # Trigger the server-side commit. For rsync version, do not delete
    # the server-side cache directory after the commit finishes.
    #
    if (-e $cachedir) {
        print("checking uploaded cache dir before committing...\n");
            isr_srun($userid, "checkparcel", "-s -p $userid/$parcel -k $main::cfg{KEYROOT}", "", 0) == 0
            or errexit("Something went wrong during upload.  Aborting with no change to the remote parcel.\n");
	print("Committing updates on content server...\n")
	    if $main::verbose;
	message("INFO", "Begin server side commit");
	isr_srun($userid, "commit", "-p $userid/$parcel -r", "", 0) == 0
	    or errexit("Server-side commit of parcel $userid/$parcel failed.");
	message("INFO", "End server side commit");
    }

    # If requested, check the newly committed version for consistency
    if (!$main::nocheckstate) {
	isr_srun($userid,
	     "checkparcel", 
	     "-p $userid/$parcel -k $main::cfg{KEYROOT}",
	     "", 0) == 0
		 or errexit("Something went wrong during commit.  Remote parcel is inconsistent.");
    }

    #
    # If the server-side commit was successful, then do the
    # client-side commit. 
    print "Committing updates on client...\n"
	if $main::verbose;
    isr_priv_clientcommit($userid, $parcel, $isrdir);

    return $Isr::ESUCCESS;

}

#
# isr_priv_clientcommit - Commit state on the client.  First, copy the
#     memory image, keyring, and index.lev1 from cache/ to last/, so that the
#     client-side last remains consistent with the server-side last/.
#     Second, move any dirty hdk chunks from the local cache to the hoard
#     cache so that the hoard cache stays fully populated.
#
sub isr_priv_clientcommit($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $chunksperdir;
    my $chunksize;
    my $numdirtybytes;
    my $dirtyblocks;
    my $line1;
    my $line2;
    my $chunkindex;
    my $chunkdir;
    my $chunkfile;
    my $cachefile;
    my $hoardfile;
    my $i;
    my $tag;
    my $key;

    my $parceldir = "$isrdir/$parcel";
    my $hoarddir = "$isrdir/$parcel-hoard";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $tmpdir = "$parceldir/tmp";

    my @chunkdiffs = ();
    my @tags = ();

    #
    # Create a hoard cache if necessary
    #
    if (!-e $hoarddir) {
	mktree($hoarddir)
	    or errexit("Unable to create $hoarddir");
    }
    
    #
    # Identify the dirty hdk files in the local cache
    #
    open(INFILE1, "$cachedir/keyring")
        or unix_errexit("Unable to open $cachedir/keyring");
    open(INFILE2, "$lastdir/keyring")
        or unix_errexit("Unable to open $lastdir/keyring");
    $i = 0;
    $dirtyblocks = 0;
    while ($line1 = <INFILE1>) {
        $line2 = <INFILE2>;
        if ($line1 ne $line2) {
	    chomp $line1;
	    ($tag, $key) = split(" ", $line1);
	    $chunkdiffs[$dirtyblocks] = $i;
	    $tags[$dirtyblocks++] = $tag;
        }
        $i++;
    }
    close INFILE1
        or unix_errexit("Unable to close $cachedir/keyring");
    close INFILE2
        or unix_errexit("Unable to close $lastdir/keyring");

    #
    # Now that we have determined the dirty disk state, we can copy
    # the memory image, keyring, and index.lev1 from cache to last
    #
    message("INFO", "Client side commit - start copying memory image");
    mysystem("cp -f $cachedir/cfg/* $lastdir/cfg") == 0
	or system_errexit("Unable to copy memory image from $cachedir to $lastdir/cfg.");
    mysystem("cp -f $cachedir/keyring $lastdir") == 0
	or system_errexit("Unable to copy keyring from $cachedir to $lastdir.");
    mysystem("cp -f $cachedir/hdk/index.lev1 $lastdir/hdk") == 0
        or system_errexit("Unable to copy index.lev1 from $cachedir to $lastdir.");
    message("INFO", "Client side commit - finish copying memory image");

    #
    # Move any dirty cache chunks to the hoard cache
    #
    message("INFO", "Client side commit - start moving hoard chunks");
    $chunksperdir = get_value("$cachedir/hdk/index.lev1", "CHUNKSPERDIR");
    $chunksize = get_value("$cachedir/hdk/index.lev1", "CHUNKSIZE");
    $numdirtybytes = $chunksize * $dirtyblocks;

    for ($i = 0; $i < $dirtyblocks; $i++) {

	# Determine the location of the cache file
	$chunkindex = $chunkdiffs[$i];
	$chunkdir = sprintf("%04d", get_dirnum($chunkindex, $chunksperdir));
	$chunkfile = sprintf("%04d", get_chunknum($chunkindex, $chunksperdir));
	$cachefile = "$tmpdir/cache/hdk/$chunkdir/$chunkfile";

	# Determine the location of the hoard file
	$tag = $tags[$i];
	$hoardfile = "$hoarddir/$tag";

	# Now move the dirty chunk to the hoard cache
	rename($cachefile, $hoardfile)
	    or unix_errexit("Unable to move $cachefile to $hoardfile.");
	print "$i: Moved $chunkdir/$chunkfile to $tag.\n"
	    if $main::verbose > 1;
	emit_hdk_progressmeter(($i+1)*$chunksize, $numdirtybytes);
    }
    reset_cursor();
    message("INFO", "Client side commit - finish moving hoard chunks");
    print "Moved $dirtyblocks dirty blocks to the hoard cache.\n"
	if $main::verbose > 1;

    # 
    # Sync because we're paranoid
    #
    sys_sync();
    sys_sync();
    return $Isr::ESUCCESS;
}

#
# isr_priv_checkcache - Checks a cache hdk for self-consistency
#
sub isr_priv_checkcache ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;
    
    my $parceldir = "$isrdir/$parcel";
    my $cachedir = "$parceldir/cache";

    if (!-e $cachedir) {
	return 0;
    }

    #
    # Verify that each block in cache has a valid keyring tag
    # 
    mysystem("$Isr::ISRCLIENTBIN/vulpes --cache $cachedir/hdk --keyring $cachedir/keyring $cachedir/cfg/keyring.bin --check --log /dev/null ':' 0x0 $Isr::CONSOLE_LOGMASK") == 0
    	or errexit("Could not validate cache");
}

#
# isr_priv_cleanhoard - perform garbage collection on hoard cache at sync time
# 
sub isr_priv_cleanhoard ($$$) {
    my $userid = shift;
    my $parcel = shift;
    my $isrdir = shift;

    my $i;
    my $numchunks;
    my $chunk;
    my $maxchunks;
    my $tag;
    
    my $parceldir = "$isrdir/$parcel";
    my $lastdir = "$parceldir/last";
    my $cachedir = "$parceldir/cache";
    my $hoarddir = "$isrdir/$parcel-hoard";

    my $deletecnt = 0;

    my %filehash = ();
    my @files = ();

    my @keyring;
    my $numkeys;


    print "Garbage collecting hoard cache..."
	if $main::verbose;

    #
    # Simple cases where nothing is hoarded or cached
    #    
    if ((!-e "$cachedir/keyring") || (!-d $hoarddir)) {
	print "\n"
	    if $main::verbose;
	return;
    }
    
    # Get the keyring from the local cache
    @keyring = load_keyring("$cachedir/keyring");
    $numkeys = scalar(@keyring);
    

    # Get a list of file in the hoard cache
    if (!opendir(DIR, "$hoarddir")) {
	err("Unable to open hoard cache ($hoarddir) for garbage collection\n");
	return;
    }
    @files = grep(!/^[\._]/, readdir(DIR)); # elide . and ..
    closedir(DIR);

    # Initially mark each file for removal
    %filehash = ();
    foreach $tag (@files) {
	$filehash{$tag} = 1;
    }

    # Exempt each file whose tag is in the keyring from removal
    for ($i = 0; $i < $numkeys; $i++) {
	if ($filehash{$keyring[$i][0]} == 1) { 
	    $filehash{$keyring[$i][0]} = 0;
	}
    }

    # Remove any files that are not exempted from removal
    foreach $tag (keys %filehash) {
	if ($filehash{$tag} == 1) {
	    unlink("$hoarddir/$tag");
	    $deletecnt++;
	}
    }

    print " (Deleted $deletecnt unused chunks)\n"
	if $main::verbose;

}

# Every Perl module ends with true;
1;
