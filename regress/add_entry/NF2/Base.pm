#############################################################
# $Id: Base.pm 3909 2008-06-06 03:31:57Z brandonh $
#
# Module provides basic functions for use by NF2 Perl scripts.
#
# Revisions:
#
##############################################################

use Test::Base;

package NF::Base;
use Exporter;
@ISA = ('Exporter');
@EXPORT = qw( &check_NF2_vars_set
            );

##############################################################
#
# Check that the user has set up their environment correctly.
#
##############################################################
sub check_NF2_vars_set {

  my @nf2_vars = qw(NF_ROOT NF_DESIGN_DIR NF_WORK_DIR);

  for (@nf2_vars) {
    my_die ("Please set shell variable $_ and try again.")
      unless defined $ENV{$_};
  }

}

# Always end library in 1
1;
