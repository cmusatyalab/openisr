#######################################################################
# IsrConfigTie.pm - Class that can be tied to a hash, such that lookups
#                   for nonexistent values cause errexit() to be called
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

package IsrConfigTie;
use strict;
use warnings;
use Tie::Hash;
# Inherit almost everything from the standard hash implementation
our @ISA = "Tie::StdHash";

sub FETCH ($$) {
    my $self = shift;
    my $key = shift;
    
    if (exists $self->{$key}) {
	return $self->{$key};
    } else {
	main::errexit("Couldn't find lookup key $key");
    }
}

1;
