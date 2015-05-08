#####################################
# vim:set shiftwidth=2 softtabstop=2 expandtab:
#
# $Id$
# author: Jad Naous jnaous@stanford.edu
# Provides functions to populate the flow
# tables and generate packets
#####################################

package NFOpenFlowTester;
use strict;
use POSIX;
use List::Util qw[min max];

use OpenFlowLib;
use NFUtils::SimplePacket;
use NF::PacketGen;
use NF::RegressLib;
use SimLib;
use Time::HiRes qw( usleep );
use Test::TestLib;

use constant DELAY_US_FLD => 'delay_us';
use constant EXACT_INDICES_FLD => 'exact_indices';
use constant WILDCARD_INDICES_FLD => 'wildcard_indices';

use constant WILDCARD => 'wildcard';

use constant START_DELAY => 'start_delay';
use constant NUM_ITERATIONS => 'num_iterations';
use constant NUM_PKTS => 'num_pkts';
use constant NUM_FLOW_ENTRIES => 'num_flow_entries';
use constant TABLE => 'table';
use constant FLOW_ENTRY_FIELDS => 'flow_entry_fields';
use constant PKT_FIELDS => 'pkt_fields';
use constant EXP_PKT_FIELDS => 'exp_pkt_fields';
use constant OUTPUT_PORTS => 'output_ports';
use constant NF2_ACTION_FLAG => 'nf2_action_flag';
use constant SET_VLAN_VID => 'set_vlan_vid';
use constant SET_VLAN_PCP => 'set_vlan_pcp';
use constant SET_DL_SRC => 'set_dl_src';
use constant SET_DL_DST => 'set_dl_dst';
use constant SET_NW_SRC => 'set_nw_src';
use constant SET_NW_DST => 'set_nw_dst';
use constant IFACE_MAP => 'ifaceMap';

###############################################################################
# This function populates the flow tables with random entries
# according to the possible fields provided.
#
# Parameters:
#   $table          OpenFlowTable object to which we want to write
#   $fields         reference to hash of lists of possible fields. The possible fields
#                   are the fields of a NFUtils::SimplePacket. It is possible to specify WILDCARD as
#                   a choice meaning the field will not be added.
#                     e.g {NFUtils::SimplePacket::IP_SRC() => ["192.145.32.23", "123.44.5.7", WILDCARD],
#                          NFUtils::SimplePacket::VLAN_TAG() => [0xffff, WILDCARD], ...}
#   $num_entries    number of random entries to add
#   $output_ports   reference to a list of one-hot encoded output ports
#                     e.g. [0x10, 0x40, 0x14, ...]
#
# Returns a hash that has as fields:
#   DELAY_US_FLD()         => number of microseconds needed as
#                             a rough estimate
#   EXACT_INDICES_FLD()    => reference to list of indices written in the exact table
#   WILDCARD_INDICES_FLD() => reference to list of indices written in the wildcard table
#
sub fillFlowTables {
  my $table = shift;         # OpenFlowTable
  my $fields = shift;        # reference to hash of lists of possible fields
  my $num_entries = shift;   # total number of entries to write
  my $output_ports = shift;  # reference to list of one-hot encoded output ports
  my $nf2_action_flag = shift;
  my $set_vlan_vid = shift;
  my $set_vlan_pcp = shift;
  my $set_dl_src = shift;
  my $set_dl_dst = shift;
  my $set_nw_src = shift;
  my $set_nw_dst = shift;
  my $delay_us = 0;
  my %indices = (exact => [],
                 wildcard => []);
  my $wildInd = 0;
  foreach (1..$num_entries){
    my %flow_args = ();

    # fill fields
    while( my ($field, $list) = (each %{$fields}) ){
      $flow_args{$field} = $list->[int(rand(scalar @{$list}))];
      delete $flow_args{$field} if($flow_args{$field} eq 'wildcard');
    }

    # print "creating entry from following fields:\n";
    # while( my ($field, $val) = (each %flow_args) ){
    #   print "$field: $val\n";
    # }

    # create entry
    my $flow = OpenFlowHdr->new(%flow_args);

    # select actions
    my $outport = $output_ports->[int(rand(scalar @{$output_ports}))];
    my $action = OpenFlowAction->new('forward' => $outport,
                                     'nf2_action_flag' => $nf2_action_flag,
                                     'set_vlan_vid' => $set_vlan_vid,
                                     'set_vlan_pcp' => $set_vlan_pcp,
                                     'set_dl_src' => $set_dl_src,
                                     'set_dl_dst' => $set_dl_dst,
                                     'set_nw_src' => $set_nw_src,
                                     'set_nw_dst' => $set_nw_dst);

    # insert into table, and store location where
    # it was stored for later removal
    my $type = $flow->getType();
    push @{$indices{$type}}, $table->addEntry($flow, $action, $type, $wildInd++);
  }

  $delay_us += $num_entries*15 + 5;

  return (DELAY_US_FLD() => $delay_us,
          EXACT_INDICES_FLD() => $indices{exact},
          WILDCARD_INDICES_FLD() => $indices{wildcard});
}

###############################################################################
# This function generates random packets according to the provided parameters
# provided, consults the given table and calls the given function with the
# provided args for each packet.
#
# Parameters:
#   $fields         reference to hash of lists of possible fields. The possible fields
#                   are the fields of a NFUtils::SimplePacket. It is possible to specify WILDCARD
#                   as a choice meaning it will not be added, and will probably be random.
#                     e.g {NFUtils::SimplePacket::IP_SRC() => ["192.145.32.23", "123.44.5.7", WILDCARD],
#                          NFUtils::SimplePacket::VLAN_TAG() => [0xffff, WILDCARD], ...}
#   $exp_fields     not used in this function.
#   $num_pkt        number of pkts to generate
#   $pktFunc        reference to a function that takes as parameters
#                    ($pkt,           # generated NFUtils::SimplePacket
#                     $exp_pkt,       # generated NFUtils::SimplePacket. Expected packet.
#                     $pkt_num,       # number of the pkt in this run
#                     $pktFuncArgs)   # passed to the generatePkts function
#                    and returns the estimated number of nanoseconds needed to execute.
#   $pktFuncArgs    passed to the $pktFunc function when called
#
# Returns:
#   number of microseconds needed as a rough estimate
#
sub generatePkts {
  my $fields = shift;
  die "Fields have to be defined for generatePkts.\n" unless defined $fields;

  # "exp_fields" is not used in this function.
  # We'll expect the same packet we have sent.
  my $exp_fields = shift;

  my $num_pkts = shift;
  die "num_pkts have to be defined for generatePkts.\n" unless defined $num_pkts;

  my $pktFunc = shift;
  my @pktFuncArgs = @_;
  $pktFunc = sub{0;} unless defined $pktFunc;

  my $delay_ns = 0;

  my @delays = (0) x 16;

  foreach (1..$num_pkts) {
    # create arguments for the packet
    my %pkt_args = ();
    #print "Pkt num $_:\n";
    while( my ($field, $list) = (each %{$fields}) ){
      $pkt_args{$field} = $list->[int(rand(scalar @{$list}))];
      #printf "field:$field, value: $pkt_args{$field}\n";
      if($pkt_args{$field} eq WILDCARD) {
        if($field eq NFUtils::SimplePacket::VLAN_TAG) {
          # make it so that half have vlans and half don't
          $pkt_args{$field} = int(rand(0xfff));
          delete $pkt_args{$field} if($pkt_args{$field} > 0x07ff);
        }
        elsif($field eq NFUtils::SimplePacket::PKT_LEN) {
          $pkt_args{$field} = int(rand(250)) + 60;
        }
        elsif($field eq NFUtils::SimplePacket::SRC_PORT) {
          $pkt_args{$field} = int(rand(8));
        }
        else {
          delete $pkt_args{$field};
        }
        #printf "finally value: $pkt_args{$field}\n" if defined $pkt_args{$field};
      }
    }

    # create packet itself
    my $pkt = NFUtils::SimplePacket->new(%pkt_args);

    # We'll expect the same packet as we have sent.
    my $exp_pkt = $pkt;

    # Call the pktFunc on the pkt
    $delay_ns = $pktFunc->($pkt, $exp_pkt, $_, @pktFuncArgs);

    my $src_port = $pkt->get(NFUtils::SimplePacket::SRC_PORT);
    $delays[$src_port] += $delay_ns;
  }

#  return $delay_ns/1000 + 10;
  return (max @delays)/1000 + 10;
}

###############################################################################
# This function generates outgoing packets and expected packets,
# according to the provided parameters,
# consults the given table and calls the given function with the
# provided args for each packet.
#
# Parameters:
#   $fields         reference to hash of lists of possible fields. The possible fields
#                   are the fields of a NFUtils::SimplePacket. It is possible to specify WILDCARD
#                   as a choice meaning it will not be added, and will probably be random.
#                     e.g {NFUtils::SimplePacket::IP_SRC() => ["192.145.32.23", "123.44.5.7", WILDCARD],
#                          NFUtils::SimplePacket::VLAN_TAG() => [0xffff, WILDCARD], ...}
#   $exp_fields     reference to hash of lists of possible fields for creating expected packets
#   $num_pkt        number of pkts to generate
#   $pktFunc        reference to a function that takes as parameters
#                    ($pkt,           # generated NFUtils::SimplePacket
#                     $exp_pkt,       # generated NFUtils::SimplePacket. Expected packet.
#                     $pkt_num,       # number of the pkt in this run
#                     $pktFuncArgs)   # passed to the generatePkts function
#                    and returns the estimated number of nanoseconds needed to execute.
#   $pktFuncArgs    passed to the $pktFunc function when called
#
# Returns:
#   number of microseconds needed as a rough estimate
#
sub expDifferentPkt {
  my $fields = shift;
  die "Fields have to be defined for generatePkts.\n" unless defined $fields;

  my $exp_fields = shift;
  die "Exp Fields have to be defined for generatePkts.\n" unless defined $exp_fields;

  my $num_pkts = shift;
  die "num_pkts have to be defined for generatePkts.\n" unless defined $num_pkts;

  my $pktFunc = shift;
  my @pktFuncArgs = @_;
  $pktFunc = sub{0;} unless defined $pktFunc;

  my $delay_ns = 0;

  my @delays = (0) x 16;

  foreach (1..$num_pkts) {

    # create arguments for the packet
    my %pkt_args = ();
    my %exp_pkt_args = ();
    #print "Pkt num $_:\n";

    my ($field, $list);
    my ($exp_field, $exp_list);

    while( ($field, $list) = (each %{$fields}) ){
      ($exp_field, $exp_list) = (each %{$exp_fields});
      $pkt_args{$field} = $list->[int(rand(scalar @{$list}))];
      $exp_pkt_args{$exp_field} = $exp_list->[int(rand(scalar @{$exp_list}))];
      printf "field    :$field, value: $pkt_args{$field}\n";
      printf "exp field:$exp_field, value: $pkt_args{$exp_field}\n";

      if($pkt_args{$field} eq WILDCARD) {
        if($field eq NFUtils::SimplePacket::VLAN_TAG) {
          # make it so that half have vlans and half don't
          $pkt_args{$field} = int(rand(0xfff));
          delete $pkt_args{$field} if($pkt_args{$field} > 0x07ff);
        }
        elsif($field eq NFUtils::SimplePacket::PKT_LEN) {
          $pkt_args{$field} = int(rand(250)) + 60;
        }
        elsif($field eq NFUtils::SimplePacket::SRC_PORT) {
          $pkt_args{$field} = int(rand(8));
        }
        else {
          delete $pkt_args{$field};
        }
        #printf "finally value: $pkt_args{$field}\n" if defined $pkt_args{$field};
      }
    }
    # Throw away the last exp_field
    ($exp_field, $exp_list) = (each %{$exp_fields});

    # create packet itself
    my $pkt = NFUtils::SimplePacket->new(%pkt_args,
                                         NFUtils::SimplePacket::IP_LEN() => 46,
                                         NFUtils::SimplePacket::PAYLOAD_GEN() => sub {return 0});
    my $exp_pkt = NFUtils::SimplePacket->new(%exp_pkt_args,
                                         NFUtils::SimplePacket::IP_LEN() => 46,
                                         NFUtils::SimplePacket::PAYLOAD_GEN() => sub {return 0});

    # Call the pktFunc on the pkt
    $delay_ns = $pktFunc->($pkt, $exp_pkt, $_, @pktFuncArgs);

    my $src_port = $pkt->get(NFUtils::SimplePacket::SRC_PORT);

    $delays[$src_port] += $delay_ns;

  }

#  return $delay_ns/1000 + 10;
  return (max @delays)/1000 + 10;
}

###############################################################################
# This is a function whose reference can be passed as the $pktFunc argument
# to generatePkts(). It needs the OpenFlowTable object as an additional argument. It
# basically sends the packet into the src port specified by the pkt's SRC_PORT
# field and executes the expected action resulting. Uses simulation functions.
#
# Parameters:
#   $pkt          NFUtils::SimplePacket to be sent into the hardware
#   $exp_pkt      NFUtils::SimplePacket to be expected
#   $pkt_num      number of the pkt in the batch. Unused.
#   $table        OpenFlowTable to use in determining action
#
# Returns:
#   estimate of number of nanoseconds needed to execute
#
sub simPktFunc {
  my $pkt = shift;
  my $exp_pkt = shift;
  my $pkt_num = shift;
  my $table = shift;

  my $src_port = $pkt->get(NFUtils::SimplePacket::SRC_PORT);

  # check if eth or dma ports
  if($src_port % 2 == 0) { #eth port
    my $in_port = $src_port/2 + 1;
    nf_packet_in($in_port, $pkt->get(NFUtils::SimplePacket::PKT_LEN), $main::delay, $main::batch, $pkt->hexBytes());
  }
  else {
    my $in_port = ($src_port-1)/2 + 1;
    nf_dma_data_in($pkt->get(NFUtils::SimplePacket::PKT_LEN), $main::delay, $in_port, $pkt->hexBytes());
  }
  # execute the expected actions
  my $exp_action = $table->getPktAction($src_port, $pkt);
  $exp_action->execute($exp_pkt, 1); # 1 means simulation

  return ($pkt->get(NFUtils::SimplePacket::PKT_LEN)*15 + 80);
}

################################################################################
# This function executes a predefined script which runs a specified number
# of iterations in each of which a number of entries are written into the
# exact and wildcard tables according to specified fields, then
# a number of pkts are generated according to another set of fields
# and then sent into the ports for simulation.
# The exact table is cleared after every iteration except the last.
# The script then checks the counters and gives the expected finish time to
# us in the config.txt. The input is specified as a hash
#
# Parameters:
#    START_DELAY()        => integer - time to start executing in us
#    NUM_ITERATIONS()     => integer - number of iterations to do
#    NUM_PKTS()           => integer - number of pkts to send in each iteration
#    NUM_FLOW_ENTRIES()   => integer - number of entries to write in each iter
#    TABLE()              => OpenFlowTable object to use for writing entries.
#    FLOW_ENTRY_FIELDS()  => reference to hash of references to lists (HoL).
#                              The keys are the fields of a NFUtils::SimplePacket, and the
#                              values are references to lists which have the
#                              the possible choices for that field.
#    PKT_FIELDS()         => Same format as FLOW_ENTRY_FIELDS()
#    OUTPUT_PORTS()       => reference to a list of bitmasks specifying output
#                            ports. e.g. [0x3, 0x1, 0x4, 0xFF,...]
#
# Returns:
#    Expected execution time in microseconds.
#
sub runRandomSim {
  my $genPktFunc = shift;
  my %arg = @_;

  foreach (START_DELAY, NUM_ITERATIONS, NUM_PKTS, NUM_FLOW_ENTRIES, TABLE, FLOW_ENTRY_FIELDS, PKT_FIELDS, EXP_PKT_FIELDS, OUTPUT_PORTS, NF2_ACTION_FLAG, SET_VLAN_VID, SET_VLAN_PCP, SET_DL_SRC, SET_DL_DST, SET_NW_SRC, SET_NW_DST) {
    die "ERROR: Missing field $_ for runRandomSim().\n" unless defined $arg{$_};
  }

  my $delay_us = $arg{START_DELAY()};
  my $num_iter = $arg{NUM_ITERATIONS()};
  my $num_pkts = $arg{NUM_PKTS()};
  my $num_table_entries = $arg{NUM_FLOW_ENTRIES()};
  my $table = $arg{TABLE()};
  my $outports = $arg{OUTPUT_PORTS()};

  my $nf2_action_flag = $arg{NF2_ACTION_FLAG()};
  my $set_vlan_vid = $arg{SET_VLAN_VID()};
  my $set_vlan_pcp = $arg{SET_VLAN_PCP()};
  my $set_dl_src = $arg{SET_DL_SRC()};
  my $set_dl_dst = $arg{SET_DL_DST()};
  my $set_nw_src = $arg{SET_NW_SRC()};
  my $set_nw_dst = $arg{SET_NW_DST()};

  foreach (1..$num_iter) {
    $main::delay = '@'."$delay_us".'us';

    # Fill up the flow table
    my %tableRetHash = fillFlowTables($table,
                                      $arg{FLOW_ENTRY_FIELDS()},
                                      $num_table_entries,
                                      $outports,
                                      $nf2_action_flag,
                                      $set_vlan_vid,
                                      $set_vlan_pcp,
                                      $set_dl_src,
                                      $set_dl_dst,
                                      $set_nw_src,
                                      $set_nw_dst);
    $delay_us += $tableRetHash{DELAY_US_FLD()};
    my @exact_indices = @{$tableRetHash{EXACT_INDICES_FLD()}};
    my @wildcard_indices = @{$tableRetHash{WILDCARD_INDICES_FLD()}};

    $main::delay = '@'."$delay_us".'us';

    print "***Tables before sending packets\n";
    $table->dumpEntries();

    print "***Now sending packets\n";
    # create packets, send them, execute them
    $delay_us += $genPktFunc->($arg{PKT_FIELDS()}, $arg{EXP_PKT_FIELDS()}, $num_pkts, \&simPktFunc, $table);
    $main::delay = '@'."$delay_us".'us';

    print "***Tables after sending packets\n";
    $table->dumpEntries();

    # clear the exact table except for the last iteration (the wildcard will be overwritten)
    unless($_ == $num_iter) {
      map($table->deleteEntry($_, 'exact'), @exact_indices);
      $delay_us += scalar @exact_indices;
    }
  }

  $main::delay = '@'."$delay_us".'us';
  $delay_us += $table->checkCounters();
  my $delay_ns = $delay_us*1000;
  print "*********** Expected finish time: $delay_ns ns\n";
  $main::delay = '@'."$delay_us".'us';
  return $delay_us;
}

###############################################################################
# This is a function whose reference can be passed as the $pktFunc argument
# to generatePkts(). It needs the OpenFlowTable object as an additional argument. It
# basically sends the packet into the src port specified by the pkt's SRC_PORT
# field and executes the expected action resulting. This is used for hardware tests
#
# Parameters:
#   $pkt          NFUtils::SimplePacket to be sent into the hardware
#   $pkt_num      number of the pkt in the batch. Unused.
#   $table        OpenFlowTable to use in determining action
#   $ifaceMap     array that maps port number to interface string e.g. ['nf2c0', 'eth1', ...]
#
# Returns:
#   estimate of number of nanoseconds needed to execute
#
sub regressPktFunc {
  my $pkt = shift;
  my $exp_pkt = shift;
  my $pkt_num = shift;
  my $table = shift;
  my $ifaceMap = shift;

  die "Error: undefined pkt parameter in regressPktFunc.\n" unless defined $pkt;
  die "Error: undefined pkt_num parameter in regressPktFunc.\n" unless defined $pkt_num;
  die "Error: undefined table parameter in regressPktFunc.\n" unless defined $table;
  die "Error: undefined ifaceMap parameter in regressPktFunc.\n" unless defined $ifaceMap;

  my $src_port = $pkt->get(NFUtils::SimplePacket::SRC_PORT);
  die "Error: undefined src_port in packet in regressPktFunc.\n" unless defined $src_port;

  print "regressPktFunc sending pkt out of $src_port = ".$ifaceMap->[$src_port]." : ".$pkt->hexString()."\n";
  nftest_send($ifaceMap->[$src_port], $pkt->packed());

  # execute the expected actions
  my $exp_action = $table->getPktAction($src_port, $pkt);
  $exp_action->execute($exp_pkt, 0, $ifaceMap); # 0 means regression

  return ($pkt->get(NFUtils::SimplePacket::PKT_LEN)*10 + 80);
}

################################################################################
# This function executes a predefined script which runs a specified number
# of iterations in each of which a number of entries are written into the
# exact and wildcard tables according to specified fields, then
# a number of pkts are generated according to another set of fields
# and then sent into the ports for simulation.
# The exact table is cleared after every iteration except the last.
# The script then checks the counters. The input is specified as a hash
#
# Parameters:
#    START_DELAY()        => integer - time to start executing in us
#    NUM_ITERATIONS()     => integer - number of iterations to do
#    NUM_PKTS()           => integer - number of pkts to send in each iteration
#    NUM_FLOW_ENTRIES()   => integer - number of entries to write in each iter
#    TABLE()              => OpenFlowTable object to use for writing entries.
#    FLOW_ENTRY_FIELDS()  => reference to hash of references to lists (HoL).
#                              The keys are the fields of a NFUtils::SimplePacket, and the
#                              values are references to lists which have the
#                              the possible choices for that field.
#    PKT_FIELDS()         => Same format as FLOW_ENTRY_FIELDS()
#    OUTPUT_PORTS()       => reference to a list of bitmasks specifying output
#                            ports. e.g. [0x3, 0x1, 0x4, 0xFF,...]
#    IFACE_MAP()          => Reference to array that maps port numbers to interfaces
#                            e.g [nf2c0, eth1, ...]
#
# Returns:
#    number of errors found
#
sub runRandomRegress {
  my %arg = @_;

  foreach (START_DELAY, NUM_ITERATIONS, NUM_PKTS, NUM_FLOW_ENTRIES, TABLE, FLOW_ENTRY_FIELDS, PKT_FIELDS, EXP_PKT_FIELDS, OUTPUT_PORTS, NF2_ACTION_FLAG, SET_VLAN_VID, SET_VLAN_PCP, SET_DL_SRC, SET_DL_DST, SET_NW_SRC, SET_NW_DST) {
    die "ERROR: Missing field $_ for runRandomRegress().\n" unless defined $arg{$_};
  }

  my $delay_us = 0;
  my $num_iter = $arg{NUM_ITERATIONS()};
  my $num_pkts = $arg{NUM_PKTS()};
  my $num_table_entries = $arg{NUM_FLOW_ENTRIES()};
  my $table = $arg{TABLE()};
  my $outports = $arg{OUTPUT_PORTS()};
  my $ifMap = $arg{IFACE_MAP()};

  my $nf2_action_flag = $arg{NF2_ACTION_FLAG()};
  my $set_vlan_vid = $arg{SET_VLAN_VID()};
  my $set_vlan_pcp = $arg{SET_VLAN_PCP()};
  my $set_dl_src = $arg{SET_DL_SRC()};
  my $set_dl_dst = $arg{SET_DL_DST()};
  my $set_nw_src = $arg{SET_NW_SRC()};
  my $set_nw_dst = $arg{SET_NW_DST()};

  usleep($delay_us);

  foreach (1..$num_iter) {
    # Fill up the flow table
    my %tableRetHash = fillFlowTables($table,
                                      $arg{FLOW_ENTRY_FIELDS()},
                                      $num_table_entries,
                                      $outports,
                                      $nf2_action_flag,
                                      $set_vlan_vid,
                                      $set_vlan_pcp,
                                      $set_dl_src,
                                      $set_dl_dst,
                                      $set_nw_src,
                                      $set_nw_dst);
    usleep(1000);
    $delay_us = $tableRetHash{DELAY_US_FLD()};
    usleep($delay_us);
    my @exact_indices = @{$tableRetHash{EXACT_INDICES_FLD()}};
    my @wildcard_indices = @{$tableRetHash{WILDCARD_INDICES_FLD()}};

    print "***Tables before sending packets\n";
    $table->dumpEntries();
    $table->checkTables();

    print "***Now sending packets\n";
    # create packets, send them, execute them
    $delay_us = generatePkts($arg{PKT_FIELDS()}, $arg{EXP_PKT_FIELDS()}, $num_pkts, \&regressPktFunc, $table, $ifMap);
    usleep(1000);

    print "***Tables after sending packets\n";
    $table->dumpEntries();

    # clear the exact table except for the last iteration (the wildcard will be overwritten)
    unless($_ == $num_iter) {
      map($table->deleteEntry($_, 'exact'), @exact_indices);
      $delay_us = scalar @exact_indices;
      usleep($delay_us);
    }
  }
  return $table->checkCounters();
}

sub clearHitsMissesCounters{
  nftest_regwrite('nf2c0',main::OPENFLOW_LOOKUP_WILDCARD_MISSES_REG(), 0);
  nftest_regwrite('nf2c0',main::OPENFLOW_LOOKUP_WILDCARD_HITS_REG(), 0);
  nftest_regwrite('nf2c0',main::OPENFLOW_LOOKUP_EXACT_MISSES_REG(), 0);
  nftest_regwrite('nf2c0',main::OPENFLOW_LOOKUP_EXACT_HITS_REG(), 0);

}

sub resetNF2Reg{
  nftest_regwrite('nf2c0',main::WDT_CPCI_REG_CTRL(), 0x10110);
  sleep 2;
}

1;
