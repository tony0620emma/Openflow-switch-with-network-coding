#####################################
# vim:set shiftwidth=2 softtabstop=2 expandtab:
#
# $Id$
# author: Jad Naous jnaous@stanford.edu
# This provides functions for manipulating the openflow switch.
#
#####################################

#######################################################
package main;
use reg_defines_openflow_switch;
#######################################################
# Package to manipulate a flow header specification
#
package OpenFlowHdr;
use strict;
use POSIX;

use NFUtils::GenericByteObject;
use NFUtils::SimplePacket;

# Create an entry that the hardware would match against
sub new {
  my ($class, %arg) = @_;

  my $format = getFormat();

  # set invalid fields to zero
  unless (defined $arg{NFUtils::SimplePacket::ETH_TYPE()} && $arg{NFUtils::SimplePacket::ETH_TYPE()} == NFUtils::SimplePacket::ETH_TYPE_IP) {
    $arg{NFUtils::SimplePacket::IP_SRC()} = 0;
    $arg{NFUtils::SimplePacket::IP_DST()} = 0;
    $arg{NFUtils::SimplePacket::IP_PROTO()} = 0;
  }

  unless (defined $arg{NFUtils::SimplePacket::IP_PROTO()}
          && ($arg{NFUtils::SimplePacket::IP_PROTO()} == NFUtils::SimplePacket::IP_PROTO_TCP
              || $arg{NFUtils::SimplePacket::IP_PROTO()} == NFUtils::SimplePacket::IP_PROTO_UDP) ) {
    $arg{NFUtils::SimplePacket::TRANSP_SRC()} = 0;
    $arg{NFUtils::SimplePacket::TRANSP_DST()} = 0;
  }

  my $cmp_data = NFUtils::GenericByteObject->new('format' => $format,
                                        'fields' => \%arg);
  my $cmp_dmask= NFUtils::GenericByteObject->new('format' => $format);

  my $Entry = {'cmp_data' => $cmp_data,
               'cmp_dmask' => $cmp_dmask,
               'type' => 'exact'
              };

  bless $Entry, $class;

  # add the wildcard entries if there are any
  foreach my $field (keys %{$format}) {
    if(!defined $arg{$field} && $field ne NFUtils::SimplePacket::VLAN_TAG) {
      $Entry->setType('wildcard');
      my $val;
      if($field eq NFUtils::SimplePacket::ETH_DST || $field eq NFUtils::SimplePacket::ETH_SRC) {
        $val = "FF:FF:FF:FF:FF:FF";
      } else {
        my $num_bytes = $format->{$field}->{width};
        $val = floor(2**($num_bytes*8)) - 1;
      }
      $Entry->setCmpDMask($field, $val);
    }
    elsif(!defined $arg{$field} && $field eq NFUtils::SimplePacket::VLAN_TAG) {
      $Entry->setType('wildcard');
      $Entry->setCmpData($field, 0xffff);
      $Entry->setCmpDMask($field, 0xffff);
    }
  }

  return $Entry;
}

# Returns a hash that specifies what the fields we match against are
# and how they are organized to be written to hardware.
# note: All widths are in bytes. All fields have to be of length
#       which is a multiple of 8 bits.
# The format has to be specified in little endian
sub getFormat {
  return { NFUtils::SimplePacket::TRANSP_DST() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_TRANSP_DST_POS()/8 - main::OPENFLOW_ENTRY_TRANSP_DST_WIDTH()/8,
                                          'width' => main::OPENFLOW_ENTRY_TRANSP_DST_WIDTH()/8,
                                          'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                          'from_bytes' => \&ByteArrayUtils::bytes_to_int},
           NFUtils::SimplePacket::TRANSP_SRC() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_TRANSP_SRC_POS()/8 - main::OPENFLOW_ENTRY_TRANSP_SRC_WIDTH()/8,
                                          'width' => main::OPENFLOW_ENTRY_TRANSP_SRC_WIDTH()/8,
                                          'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                          'from_bytes' => \&ByteArrayUtils::bytes_to_int},
           NFUtils::SimplePacket::IP_PROTO() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_IP_PROTO_POS()/8 - main::OPENFLOW_ENTRY_IP_PROTO_WIDTH()/8,
                                        'width' => main::OPENFLOW_ENTRY_IP_PROTO_WIDTH()/8,
                                        'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                        'from_bytes' => \&ByteArrayUtils::bytes_to_int},
           NFUtils::SimplePacket::IP_DST() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_IP_DST_POS()/8 - main::OPENFLOW_ENTRY_IP_DST_WIDTH()/8,
                                      'width' => main::OPENFLOW_ENTRY_IP_DST_WIDTH()/8,
                                      'to_bytes' => \&ByteArrayUtils::ip_to_bytes,
                                      'from_bytes' => \&ByteArrayUtils::bytes_to_ip},
           NFUtils::SimplePacket::IP_SRC() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_IP_SRC_POS()/8 - main::OPENFLOW_ENTRY_IP_SRC_WIDTH()/8,
                                      'width' => main::OPENFLOW_ENTRY_IP_SRC_WIDTH()/8,
                                      'to_bytes' => \&ByteArrayUtils::ip_to_bytes,
                                      'from_bytes' => \&ByteArrayUtils::bytes_to_ip},
           NFUtils::SimplePacket::ETH_TYPE() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_ETH_TYPE_POS()/8 - main::OPENFLOW_ENTRY_ETH_TYPE_WIDTH()/8,
                                        'width' => main::OPENFLOW_ENTRY_ETH_TYPE_WIDTH()/8,
                                        'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                        'from_bytes' => \&ByteArrayUtils::bytes_to_int},
           NFUtils::SimplePacket::ETH_DST() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_ETH_DST_POS()/8 - main::OPENFLOW_ENTRY_ETH_DST_WIDTH()/8,
                                       'width' => main::OPENFLOW_ENTRY_ETH_DST_WIDTH()/8,
                                       'to_bytes' => \&ByteArrayUtils::mac_to_bytes,
                                       'from_bytes' => \&ByteArrayUtils::bytes_to_mac},
           NFUtils::SimplePacket::ETH_SRC() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_ETH_SRC_POS()/8 - main::OPENFLOW_ENTRY_ETH_SRC_WIDTH()/8,
                                       'width' => main::OPENFLOW_ENTRY_ETH_SRC_WIDTH()/8,
                                       'to_bytes' => \&ByteArrayUtils::mac_to_bytes,
                                       'from_bytes' => \&ByteArrayUtils::bytes_to_mac},
           NFUtils::SimplePacket::SRC_PORT() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_SRC_PORT_POS()/8 - main::OPENFLOW_ENTRY_SRC_PORT_WIDTH()/8,
                                        'width' => main::OPENFLOW_ENTRY_SRC_PORT_WIDTH()/8,
                                        'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                        'from_bytes' => \&ByteArrayUtils::bytes_to_int},
           NFUtils::SimplePacket::IP_TOS() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_IP_TOS_POS()/8 - main::OPENFLOW_ENTRY_IP_TOS_WIDTH()/8,
                                        'width' => main::OPENFLOW_ENTRY_IP_TOS_WIDTH()/8,
                                        'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                        'from_bytes' => \&ByteArrayUtils::bytes_to_int},
           NFUtils::SimplePacket::VLAN_TAG() => {'pos' => main::OPENFLOW_ENTRY_WIDTH()/8 - main::OPENFLOW_ENTRY_VLAN_ID_POS()/8 - main::OPENFLOW_ENTRY_VLAN_ID_WIDTH()/8,
                                        'width' => main::OPENFLOW_ENTRY_VLAN_ID_WIDTH()/8,
                                        'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                        'from_bytes' => \&ByteArrayUtils::bytes_to_int}
         };
}

sub getCmpDataObject {
  return shift->{cmp_data};
}

sub getCmpDMaskObject {
  return shift->{cmp_dmask};
}

sub getCmpData {
  my ($self, $field) = @_;

  return $self->{'cmp_data'}->get($field);
}

sub getCmpDMask {
  my ($self, $field) = @_;

  return $self->{'cmp_dmask'}->get($field);
}

sub setCmpData {
  my $self = shift;
  $self->{'cmp_data'}->set(@_);
}

sub setCmpDMask {
  my $self = shift;
  $self->{'cmp_dmask'}->set(@_);
}

# Gets the entry as a list of words that can be written into the table
sub cmpDataWords {
  my $self = shift;
  return $self->{'cmp_data'}->littleEndianWords();
}
sub cmpDMaskWords {
  my $self = shift;
  return $self->{'cmp_dmask'}->littleEndianWords();
}

sub getType {
  my $self = shift;
  return $self->{type};
}
sub setType {
  my $self = shift;
  $self->{type} = shift;
}

# extend the bytes to become 32 bytes and reverse
# for correct hashing
sub cmpDataBytes {
  my $self = shift;
  my @bytes = $self->{'cmp_data'}->bytes();
  @bytes = reverse @bytes;
  push @bytes, (0) x (32 - main::OPENFLOW_ENTRY_WIDTH()/8);
  return @bytes;
}

# returns 1 if this header matches the header in the parameter
sub matches {
  my $self = shift;
  my $other = shift;

  my @self_bytes_data = $self->{cmp_data}->bytes();
  my @self_bytes_dmask = $self->{cmp_dmask}->bytes();
  my @other_bytes_data = $other->{cmp_data}->bytes();
  my @other_bytes_dmask = $other->{cmp_dmask}->bytes();

  foreach my $i (0..scalar @self_bytes_data - 1) {
    if (($self_bytes_data[$i] & ~$self_bytes_dmask[$i] & ~$other_bytes_dmask[$i]) != ($other_bytes_data[$i] & ~$self_bytes_dmask[$i] & ~$other_bytes_dmask[$i])){
      return 0;
    }
  }
  return 1;
}

###############################################################
# Package to manipulate actions that can be taken on a flow
#
package OpenFlowAction;
use strict;
use POSIX;
use NF::PacketGen;
use NFUtils::GenericByteObject;
use SimLib;
use Test::TestLib;

our @ISA = ('NFUtils::GenericByteObject');

# Creates an object that specifies what the actions
# to be taken on a flow are
sub new {
  my ($class, %arg) = @_;

  my $format = {'forward' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_FORWARD_BITMASK_POS()/8 - main::OPENFLOW_FORWARD_BITMASK_WIDTH()/8,
                              'width' => main::OPENFLOW_FORWARD_BITMASK_WIDTH()/8,
                              'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                              'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'nf2_action_flag' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_NF2_ACTION_FLAG_POS()/8 - main::OPENFLOW_NF2_ACTION_FLAG_WIDTH()/8,
                                     'width' => main::OPENFLOW_NF2_ACTION_FLAG_WIDTH()/8,
                                     'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                     'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_vlan_vid' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_VLAN_VID_POS()/8 - main::OPENFLOW_SET_VLAN_VID_WIDTH()/8,
                                  'width' => main::OPENFLOW_SET_VLAN_VID_WIDTH()/8,
                                  'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                  'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_vlan_pcp' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_VLAN_PCP_POS()/8 - main::OPENFLOW_SET_VLAN_PCP_WIDTH()/8,
                                  'width' => main::OPENFLOW_SET_VLAN_PCP_WIDTH()/8,
                                  'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                  'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_dl_src' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_DL_SRC_POS()/8 - main::OPENFLOW_SET_DL_SRC_WIDTH()/8,
                                'width' => main::OPENFLOW_SET_DL_SRC_WIDTH()/8,
                                'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_dl_dst' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_DL_DST_POS()/8 - main::OPENFLOW_SET_DL_DST_WIDTH()/8,
                                'width' => main::OPENFLOW_SET_DL_DST_WIDTH()/8,
                                'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_nw_src' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_NW_SRC_POS()/8 - main::OPENFLOW_SET_NW_SRC_WIDTH()/8,
                                'width' => main::OPENFLOW_SET_NW_SRC_WIDTH()/8,
                                'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_nw_dst' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_NW_DST_POS()/8 - main::OPENFLOW_SET_NW_DST_WIDTH()/8,
                                'width' => main::OPENFLOW_SET_NW_DST_WIDTH()/8,
                                'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_tp_src' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_TP_SRC_POS()/8 - main::OPENFLOW_SET_TP_SRC_WIDTH()/8,
                                'width' => main::OPENFLOW_SET_TP_SRC_WIDTH()/8,
                                'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'set_tp_dst' => {'pos' => main::OPENFLOW_ACTION_WIDTH()/8 - main::OPENFLOW_SET_TP_DST_POS()/8 - main::OPENFLOW_SET_TP_DST_WIDTH()/8,
                                'width' => main::OPENFLOW_SET_TP_DST_WIDTH()/8,
                                'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                                'from_bytes' => \&ByteArrayUtils::bytes_to_int},
               'padding' => {'pos' => 0,
                             'width' => 9,
                             'to_bytes' => \&ByteArrayUtils::int_to_bytes,
                             'from_bytes' => \&ByteArrayUtils::bytes_to_int},

               };

  my $Entry = {};

  bless $Entry, $class;

#  $arg{pkt_trim} = 0xffff unless(defined $arg{pkt_trim});

  $Entry = $class->SUPER::new('format' => $format,
                              'fields' => \%arg
                             );
  $Entry;
}

# sets the expected results for a packet if
# it has these actions specified on it.
sub execute {
  my $self = shift;
  my $pkt  = shift;     # NFUtils::SimplePacket which we will execute actions on
  my $execType  = shift;# specifies if we are running in a simulation context or debugging context
                        # if set to 1, then simulating, if set to 2, then debugging, otherwise
                        # running on real hardware.
  my $ifmap = shift;    # Array that maps port numbers to iface names. e.g: ['nf2c0', 'eth1', ...]
                        # Only needed when running in real hardware context

  die "Error in Action->execute(): Need to specify pkt as parameter 1 of 2 (3 for real hw) for execute()\n" unless(defined $pkt);
  die "Error in Action->execute(): Need to specify execution type as parameter 2 of 2 (3 for real hw) for execute()\n" unless(defined $execType);
  die "Error in Action->execute(): Need to specify interface map as parameter 3 of 3 for execute() in real hw context.\n" unless(defined $ifmap || $execType == 1 || $execType == 2);

  my $forward_onehot = $self->get('forward');
  if (defined $forward_onehot) {
    for (my $port = 0; $port < 8; $port++) {
      if($forward_onehot & 1 == 1) {
        if($execType==1) {
          # Ethernet port
          if($port % 2 == 0) {
            my $tmp = ($port/2) + 1;
#           print "Pkt expected on eth port $tmp\n";
            nf_expected_packet($tmp, $pkt->size(), $pkt->hexBytes());
          }
          # CPU port
          else {
            my $tmp = ($port-1)/2 + 1;
#           print "Pkt expected on dma port $tmp\n";
            nf_expected_dma_data($tmp, $pkt->size(), $pkt->hexBytes());
          }
        }
        elsif($execType==2){
          printf "Expecting packet size %d to be forwarded on port $port: %s\n", $pkt->size(), $pkt->hexBytes();
        }
        else {
          printf "Expecting packet size %d to be forwarded on port $port: %s = %s\n", $pkt->size(), $ifmap->[$port], $pkt->hexBytes();
          nftest_expect($ifmap->[$port], $pkt->packed());
        }
      }
      $forward_onehot >>= 1;
    }
  }

}


################################################################
# Utilities to manipulate the hardware flow table
#
package OpenFlowTable;
use strict;
use POSIX;

use SimLib;
use NF::RegressLib;
use NF::PacketGen;
use NFUtils::CRCLib;
use NFUtils::SimplePacket;

sub new {
  my ($class, %arg) = @_;

  my $table = {'wildcard' => { entries => [],
                               hits => 0,
                               misses => 0
                             },
               'exact' =>  { entries => {},
                             hits => 0,
                             misses => 0
                           },
               'dropCounters' => [(0) x 8] # one counter per port
              };

  foreach (0..main::OPENFLOW_WILDCARD_TABLE_SIZE()-1){
    $table->{wildcard}->{entries}->[$_] = {};
  }

  if(defined $arg{'debug'} && $arg{'debug'}) {
    $table->{'reg_write'} = sub {};
    $table->{'reg_read'} = sub {};
    $table->{'reg_read_expect'} = sub {};
    $table->{'reg_read_expect_masked'} = sub {};
    $table->{'debug'} = 1;
  }
  elsif(defined $arg{'simulation'} && $arg{'simulation'}) {
    $table->{'reg_write'} = \&NF::PacketGen::nf_PCI_write32;
    $table->{'reg_read'} = undef;
    $table->{'reg_read_expect'} = \&NF::PacketGen::nf_PCI_read32;
    $table->{'reg_read_expect_masked'} = \&NF::PacketGen::nf_PCI_read32_masked;
    $table->{'simulation'} = 1;
  }
  else {
    die "Error in OpenFlowTable->new(): Need to define an iface to use to contact the hardware. e.g. 'iface' => nf2c0. Otherwise specify simulation ('simulation' => 1).\n" unless defined $arg{'iface'};
    $table->{'reg_write'} = \&NF::RegressLib::nftest_regwrite;
    $table->{'reg_read'} = \&NF::RegressLib::nftest_regread;
    $table->{'reg_read_expect'} = \&NF::RegressLib::nftest_regread_expect;
    $table->{'reg_read_expect_masked'} = \&NF::RegressLib::nftest_regread_expect;
    $table->{'reg_aux'} = [$arg{'iface'}];
  }

  # Initialize hashing objects for exact match
  $table->{exact}->{hash0} = CRC32Lib->new(polynomial => CRC32Lib::ETH_CRC_POLY);
  $table->{exact}->{hash1} = CRC32Lib->new(polynomial => CRC32Lib::OTHER_CRC_POLY);

  bless $table, $class;

  $table->{wildcard}->{write} = \&writeWildcardEntry;
  $table->{wildcard}->{find}  = \&findWildcardEntry;
  $table->{wildcard}->{delete}= \&deleteWildcardEntry;
  $table->{exact}->{write}    = \&writeExactEntry;
  $table->{exact}->{find}     = \&findExactEntry;
  $table->{exact}->{delete}   = \&deleteExactEntry;

  return $table;
}

# Add an entry into the hardware flow table
sub addEntry {
  my ($self, $hdr, $action, $table_name, $index) = @_;

  die "Need to specify valid header as parameter 1 of addEntry().\n" unless defined $hdr;
  die "Need to specify valid action as parameter 2 of addEntry().\n" unless defined $action;

  if(!defined $table_name) {
    $table_name = $hdr->{'type'};
  }
  elsif ($table_name ne 'wildcard' && $table_name ne 'exact') {
    die "unknown table name $table_name. Has to be either wildcard or exact.\n";
  }

  return $self->{$table_name}->{write}->($self, $hdr, $action, $index);
}

# deletes an entry
sub deleteEntry {
  my ($self, $index, $table_name) = @_;

  die "Need to give index as first parameter of deleteEntry().\n" unless defined $index;
  die "Need to give index as second parameter of deleteEntry().\n" unless defined $table_name;

  die "Unknown table $table_name in deleteEntry().\n" if($table_name ne 'wildcard' && $table_name ne 'exact');

  return $self->{$table_name}->{delete}->($self, $index);
}

# writes an entry into the wildcard table
sub writeWildcardEntry {
  my ($self, $hdr, $action, $index) = @_;
  die "Need to specify valid header as parameter 1 of writeWildcardEntry().\n" unless defined $hdr;
  die "Need to specify valid action as parameter 2 of writeWildcardEntry().\n" unless defined $action;
  die "Need to specify index as parameter 3 of writeWildcardEntry().\n" unless defined $index;

  # check that the index is within the table size
  die "Error: Index to write wildcard entry ($index) is larger than the table size.\n"
    unless ($index < main::OPENFLOW_WILDCARD_TABLE_SIZE());

  # Store in the table in memory
  $self->{wildcard}->{entries}->[$index]->{header} = $hdr;
  $self->{wildcard}->{entries}->[$index]->{action} = $action;
  $self->{wildcard}->{entries}->[$index]->{pkts_hit} = 0;
  $self->{wildcard}->{entries}->[$index]->{bytes_hit} = 0;

  # write the header
  my @hdr_data_words = $hdr->cmpDataWords();
  my @hdr_dmask_words = $hdr->cmpDMaskWords();
  print "Wildcard write: ";
  foreach my $i (0..$#hdr_data_words) {
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG() + $i*4,
                           $hdr_data_words[$i]);
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG() + $i*4,
                           $hdr_dmask_words[$i]);
    printf "%08x ", $hdr_data_words[$i];
  }
  print "\n";

  # write the actions
  my @action_words = $action->littleEndianWords();
  foreach my $i (0..$#action_words) {
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG() + $i*4,
                           $action_words[$i]);
  }

  # write the index
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG(),
                         $index);

  # reset the counters associated with this entry
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG() + $index*4,
                         0);
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG() + $index*4,
                         0);
  return $index;
}

sub writeExactEntry {
  my ($self, $hdr, $action) = @_;

  die "Need to specify valid header as parameter 1 of writeExactEntry().\n" unless defined $hdr;
  die "Need to specify valid action as parameter 2 of writeExactEntry().\n" unless defined $action;

  # find the hashes of the header. Use the lower 15 bits.
  my $hash0 = (0x7fff & $self->{exact}->{hash0}->calculate($hdr->cmpDataBytes())) << 7;
  my $hash1 = (0x7fff & $self->{exact}->{hash1}->calculate($hdr->cmpDataBytes())) << 7;
  printf "write: hash0: %x hash1: %x\n", $hash0>>7, $hash1>>7;

  # check which entry is free and select it to write to or overwrite previous entry
  # We shift by 7 since each entry uses 32 32-bit words (5bits) and
  # addresses should be byte not word addresses so shift by 2bits
  my $index;
  if(defined $self->{exact}->{entries}->{$hash0}
     && $hdr->matches($self->{exact}->{entries}->{$hash0}->{header})) {
    $index = $hash0;
  }
  elsif(defined $self->{exact}->{entries}->{$hash1}
     && $hdr->matches($self->{exact}->{entries}->{$hash1}->{header})) {
    $index = $hash1;
  }
  elsif(!defined $self->{exact}->{entries}->{$hash0}) {
    $index = $hash0;
  }
  elsif(!defined $self->{exact}->{entries}->{$hash1}) {
    $index = $hash1;
  }
  else {
    die "ERROR: Entry clashes with both indices in the exact match table.\n";
  }

  printf "write: Writing entry %s into %x hash %x\n", $hdr->getCmpDataObject()->hexString(), $index, $index>>7;

  # Store in the table in memory
  $self->{exact}->{entries}->{$index}->{header} = $hdr;
  $self->{exact}->{entries}->{$index}->{action} = $action;
  $self->{exact}->{entries}->{$index}->{pkts_hit} = 0;
  $self->{exact}->{entries}->{$index}->{bytes_hit} = 0;

  # write to hardware
  my @hdr_data_words = $hdr->cmpDataWords();
  # The most significant word will have a valid bit in the MSb position
  $hdr_data_words[$#hdr_data_words] |= 0x80000000;

  # write the header
  foreach my $i (0..$#hdr_data_words) {
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_HDR_BASE_POS()*4 + $i*4 + $index,
                           $hdr_data_words[$i]);
    printf "Writing %08x into address %08x.\n", $hdr_data_words[$i], main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_HDR_BASE_POS()*4 + $i*4 + $index;
  }

  # get the current time. We can't do this in simulation though.
  my $timestamp = 0;
  if((!defined $self->{simulation} || $self->{simulation} == 0)
     && (!defined $self->{debug} || $self->{debug} == 0)) {
    $timestamp = $self->{'reg_read'}->(@{$self->{reg_aux}},
                                       main::OPENFLOW_LOOKUP_TIMER_REG());
  }

  # write timestamp and pkt counter
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + $index,
                         ($timestamp & 0x7f) << main::OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS());
  printf "Writing %08x into address %08x.\n", ($timestamp & 0x7f) << main::OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS(), main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + $index;

  # write byte counter
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + 4 + $index,
                         0);
  printf "Writing %08x into address %08x.\n", 0, main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + 4 + $index,

  # write the actions
  my @action_words = $action->littleEndianWords();
  foreach my $i (0..$#action_words) {
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_ACTION_BASE_POS()*4 + $index + $i*4,
                           $action_words[$i]);
    printf "Writing %08x into address %08x.\n", $action_words[$i], main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_ACTION_BASE_POS()*4 + $i*4 + $index;
  }

  return $index;
}

# checks an entry in the wildcard table
sub checkWildcardEntries {
  my ($self) = @_;

  foreach my $index(0..main::OPENFLOW_WILDCARD_TABLE_SIZE()-1) {
    # get entry from the table in memory
    my $hdr = $self->{wildcard}->{entries}->[$index]->{header};
    my $action = $self->{wildcard}->{entries}->[$index]->{action};

    if(defined $hdr) {
      # write the index
      $self->{'reg_write'}->(@{$self->{reg_aux}},
                             main::OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG(),
                             $index);

    # check the header
      my @hdr_data_words = $hdr->cmpDataWords();
      my @hdr_dmask_words = $hdr->cmpDMaskWords();
      foreach my $i (0..$#hdr_data_words) {
        $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                     main::OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG() + $i*4,
                                     $hdr_data_words[$i]);
        $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                     main::OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG() + $i*4,
                                     $hdr_dmask_words[$i]);
      }

      # check the actions
      my @action_words = $action->littleEndianWords();
      foreach my $i (0..$#action_words) {
        $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                     main::OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG() + $i*4,
                                     $action_words[$i]);
      }
    }
  }
}

sub checkExactEntries {
  my ($self) = @_;

  foreach my $index(keys %{$self->{exact}->{entries}}) {
    # get entry from the table in memory
    my $hdr = $self->{exact}->{entries}->{$index}->{header};
    my $action = $self->{exact}->{entries}->{$index}->{action};

    # get words
    my @hdr_data_words = $hdr->cmpDataWords();
    # The most significant word will have a valid bit in the MSb position
    $hdr_data_words[$#hdr_data_words] |= 0x80000000;

    # check the header
    foreach my $i (0..$#hdr_data_words) {
      $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                   main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_HDR_BASE_POS()*4 + $i*4 + $index,
                                   $hdr_data_words[$i]);
    }

    # check the actions
    my @action_words = $action->littleEndianWords();
    foreach my $i (0..$#action_words) {
      $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                   main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_ACTION_BASE_POS()*4 + $index + $i*4,
                                   $action_words[$i]);
    }
  }
}

sub deleteWildcardEntry {
  my ($self, $index) = @_;
  die "Need to give index as first parameter of deleteWildcardEntry().\n" unless defined $index;

  foreach my $i (0..main::OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED() - 1) {
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG() + $i*4,
                           0);
    $self->{'reg_write'}->(@{$self->{reg_aux}},
                           main::OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG() + $i*4,
                           0);
  }

  # write the index
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG(),
                         $index);

  # reset the counters associated with this entry
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG() + $index*4,
                         0);
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG() + $index*4,
                         0);

  # delete entry from memory
  $self->{wildcard}->{entries}->[$index] = {};
}

sub deleteExactEntry {
  my ($self, $index) = @_;
  die "Need to give index as first parameter of deleteWildcardEntry().\n" unless defined $index;

  # just clear the valid bit
  $self->{'reg_write'}->(@{$self->{reg_aux}},
                         main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_HDR_BASE_POS()*4 + 7*4 + $index,
                         0);

  # delete entry from memory
  delete $self->{exact}->{entries}->{$index} if defined $self->{exact}->{entries}->{$index};
}

# returns the action that is expected to occur if
# this pkt goes into the hardware at the specified port
sub getPktAction {
  die "Error: Need input port and the packet for getPktAction to work correctly." unless (@_ == 3);
  my $self = shift;
  my $input_port = shift; # port a packet goes in through (0-15)
  my $pkt = shift;        # NFUtils::SimplePacket

  my %args = ();
  foreach my $field (keys %{OpenFlowHdr::getFormat()}) {
    if(!$pkt->contains($field)) {
      # set to zero so they don't get treated as wildcards
      if($field eq NFUtils::SimplePacket::ETH_DST || $field eq NFUtils::SimplePacket::ETH_SRC) {
        $args{$field} = "00:00:00:00:00:00";
      }
      else {
        $args{$field} = 0 unless $field eq NFUtils::SimplePacket::VLAN_TAG;
        $args{$field} = 0xffff if $field eq NFUtils::SimplePacket::VLAN_TAG;
      }
    }
    else {
      $args{$field} = $pkt->get($field);
    }
  }
  $args{NFUtils::SimplePacket::SRC_PORT()} = $input_port;

  # set invalid fields to zero
  unless (defined $args{NFUtils::SimplePacket::ETH_TYPE()} && $args{NFUtils::SimplePacket::ETH_TYPE()} == NFUtils::SimplePacket::ETH_TYPE_IP) {
    $args{NFUtils::SimplePacket::IP_SRC()} = 0;
    $args{NFUtils::SimplePacket::IP_DST()} = 0;
    $args{NFUtils::SimplePacket::IP_PROTO()} = 0;
  }

  unless (defined $args{NFUtils::SimplePacket::IP_PROTO()} && ($args{NFUtils::SimplePacket::IP_PROTO()} == NFUtils::SimplePacket::IP_PROTO_TCP
                                      || $args{NFUtils::SimplePacket::IP_PROTO()} == NFUtils::SimplePacket::IP_PROTO_UDP) ) {
    $args{NFUtils::SimplePacket::TRANSP_SRC()} = 0;
    $args{NFUtils::SimplePacket::TRANSP_DST()} = 0;
  }

  my $pktFlowHdr = OpenFlowHdr->new(%args);

  printf "getPktAction looking for: %s\n", $pktFlowHdr->getCmpDataObject()->hexString();

  my $entry = $self->{exact}->{find}->($self, $pktFlowHdr, $pkt->size());

  if(!defined $entry) {
    $entry = $self->{wildcard}->{find}->($self, $pktFlowHdr, $pkt->size());
  }
  # update wildcard miss counters
  else {
    my $temp = $self->{wildcard}->{find}->($self, $pktFlowHdr, $pkt->size(), 0);
    $self->{wildcard}->{misses}++ unless defined $temp;
  }

  return $entry->{action} if defined $entry;

  # if we still didn't find an entry
  $self->{dropCounters}->[$input_port]++;
  return OpenFlowAction->new(forward => 0);
}

# returns a reference to a hash which is the entry
# in the wildcard table corresponding to the given flow header
# otherwise, returns undef
sub findWildcardEntry {
  my $self = shift;
  my $pktFlowHdr = shift;        # NFUtils::SimplePacket
  my $pktSize = shift;
  my $updateCounters = shift;
  my $input_port = $pktFlowHdr->getCmpData(NFUtils::SimplePacket::SRC_PORT);

  $updateCounters = 1 unless defined $updateCounters;

  printf "search for header %s in wildcard table.\n", $pktFlowHdr->getCmpDataObject()->hexString();

  my $i=0;
  foreach my $entry (@{$self->{wildcard}->{entries}}) {
    if (defined $entry->{header} && $entry->{header}->matches($pktFlowHdr)) {
#      print "getPktAction: pkt matches entry $i in wildcard table\n";
      if($updateCounters == 1) {
        $self->{wildcard}->{hits}++;
        $entry->{pkts_hit}++;
        $entry->{bytes_hit} += $pktSize;
      }
      # check if the action specifies drop
      if($entry->{action}->get('forward') == 0) {
        return undef;
      }
      return $entry;
    }
    $i++;
  }
  if($updateCounters == 1) {
    $self->{wildcard}->{misses}++;
  }

  return undef;
}

# returns a reference to a hash which is the entry
# in the wildcard table corresponding to the given flow header
# otherwise, returns undef
sub findExactEntry {
  my $self = shift;
  my $pktFlowHdr = shift;        # NFUtils::SimplePacket
  my $pktSize = shift;
  my $updateCounters = shift;
  my $input_port = $pktFlowHdr->getCmpData(NFUtils::SimplePacket::SRC_PORT);

  $updateCounters = 1 unless defined $updateCounters;

  my $i=0;

  # find the hashes of the header. Use the lower 15 bits.
  my $hash0 = (0x7fff & $self->{exact}->{hash0}->calculate($pktFlowHdr->cmpDataBytes()))<<7;
  my $hash1 = (0x7fff & $self->{exact}->{hash1}->calculate($pktFlowHdr->cmpDataBytes()))<<7;

  #  entry is free and select it to write to.
  # We shift by 6 since each entry uses 16 words (4bits) and
  # addresses are byte not word addresses so each address is 4 bytes (2bits)
  my @indices = ();
  if(defined $self->{exact}->{entries}->{$hash0}) {
    push @indices, $hash0;
  }
  if(defined $self->{exact}->{entries}->{$hash1}) {
    push @indices, $hash1;
  }

  print "find: exact entry indices: ";
  map (printf("%x ", $_), @indices);
  print "\n";

  foreach my $index (@indices) {
    my $entry = $self->{exact}->{entries}->{$index};
    if($entry->{header}->matches($pktFlowHdr)) {
      if($updateCounters == 1) {
        $self->{exact}->{hits}++;
        $entry->{pkts_hit}++;
        $entry->{bytes_hit} += $pktSize;
      }
      # check if the action specifies drop
      if($entry->{action}->get('forward') == 0) {
        print "found exact entry at index $index but it's a drop\n";
        return undef;
      }
      return $entry;
    }
  }
  if($updateCounters == 1) {
    $self->{exact}->{misses}++;
  }
  print "did not find exact entry\n";
  return undef;
}

# prints out each entry of each table
sub dumpEntries {
  my $self = shift;

  my $table = $self->{exact}->{entries};
  printf "Table exact has the following entries:\n";
  foreach my $i (keys %{$table}) {
    if (defined $table->{$i}->{header}) {
      printf "%x:\theader:\t%s\n\taction:\t%s\n", $i, $table->{$i}->{header}->getCmpDataObject()->hexString(), $table->{$i}->{action}->hexString();
    }
  }

  $table = $self->{wildcard}->{entries};
  printf "Table wildcard has %d entries:\n", scalar @{$table};
  foreach my $i (0..scalar @{$table} - 1) {
    if (defined $table->[$i]->{header}) {
      printf "$i:\t header:\t%s\n", $table->[$i]->{header}->getCmpDataObject()->hexString();
      printf "\t mask   :\t%s\n", $table->[$i]->{header}->getCmpDMaskObject()->hexString();
      printf "\t action :\t%s\n", $table->[$i]->{action}->hexString();
      printf "\t pkt_hit:\t%s\n", $table->[$i]->{pkts_hit};
    }
  }
}

# Checks that the tables in memory match the hardware
sub checkTables {
  my $self = shift;
  # check each wildcard entry
  print "Checking wildcard entries.\n";
  $self->checkWildcardEntries();
  print "Checking exact entries.\n";
  $self->checkExactEntries();
}

# checks counters in the hardware tables
# returns (estimate of time, number of errors). Number of errors
# only valid in regressions.
sub checkCounters {
  my $self = shift;

  my $delay_us = 0;
  # first check the hits and misses in the wildcard table
  print "Checking wildcard table hits and misses.\n";
  $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                               main::OPENFLOW_LOOKUP_WILDCARD_MISSES_REG(),
                               $self->{wildcard}->{misses});
  print "  Expect: misses = $self->{wildcard}->{misses}\n";
  $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                               main::OPENFLOW_LOOKUP_WILDCARD_HITS_REG(),
                               $self->{wildcard}->{hits});
  print "  Expect: hits   = $self->{wildcard}->{hits}\n";

  # check the hits and misses in the exact table
  print "Checking exact table hits and misses.\n";
  $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                               main::OPENFLOW_LOOKUP_EXACT_MISSES_REG(),
                               $self->{exact}->{misses});
  print "  Expect: misses = $self->{exact}->{misses}\n";
  $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                               main::OPENFLOW_LOOKUP_EXACT_HITS_REG(),
                               $self->{exact}->{hits});
  print "  Expect: hits   = $self->{exact}->{hits}\n";

  $delay_us += 4.4;

  # check the packet drops
  print "Checking packet drops.\n";
  foreach my $i(0..(scalar @{$self->{dropCounters}})-1) {
    $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                 main::OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_0_REG() + $i*4,
                                 $self->{dropCounters}->[$i]);
    print "  Expect: NetFPGA port $i:  drops  = $self->{dropCounters}->[$i]\n";
    $delay_us += 1.1;
  }

  # check each wildcard entry
  print "Checking wildcard entry hits .\n";
  foreach my $i(0..main::OPENFLOW_WILDCARD_TABLE_SIZE()-1) {
    if(defined $self->{wildcard}->{entries}->[$i]->{header}) {
      $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                   main::OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG() + $i*4,
                                   $self->{wildcard}->{entries}->[$i]->{bytes_hit});
      print "  Expect: bytes  = $self->{wildcard}->{entries}->[$i]->{bytes_hit}\n";
      $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                   main::OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG() + $i*4,
                                   $self->{wildcard}->{entries}->[$i]->{pkts_hit});
      print "  Expect: pkts   = $self->{wildcard}->{entries}->[$i]->{pkts_hit}\n";
    # reset the counters associated with this entry
      $self->{'reg_write'}->(@{$self->{reg_aux}},
                             main::OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG() + $i*4,
                             0);
      $self->{'reg_write'}->(@{$self->{reg_aux}},
                             main::OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG() + $i*4,
                             0);
      # check that the counters were cleared
      $delay_us += 4.4;
    }
  }

  # check each exact entry
  print "Checking exact entry hits .\n";
  foreach my $i(keys %{$self->{exact}->{entries}}) {
    $self->{'reg_read_expect_masked'}->(@{$self->{reg_aux}},
                                        main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + $i,
                                        $self->{exact}->{entries}->{$i}->{pkts_hit},
                                        0xffffff);
    $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                 main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + $i + 4,
                                 $self->{exact}->{entries}->{$i}->{bytes_hit});
    print "  Expect: $self->{exact}->{entries}->{$i}->{bytes_hit}\n";
    # check that the counters were cleared
    $self->{'reg_read_expect_masked'}->(@{$self->{reg_aux}},
                                        main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + $i,
                                        0,
                                        0xffffff);
    $self->{'reg_read_expect'}->(@{$self->{reg_aux}},
                                 main::SRAM_BASE_ADDR() + main::OPENFLOW_EXACT_ENTRY_COUNTERS_POS()*4 + $i + 4,
                                 0);
    $delay_us += 4.4;
  }
  return $delay_us;
}

1;
