#
# IsrConfigTie - Class that can be tied to a hash, such that lookups for
#                nonexistent values cause errexit() to be called
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
