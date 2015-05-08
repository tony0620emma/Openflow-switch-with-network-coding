#####################################
#
# $Id: NF21RouterLib.pm 4147 2008-06-18 23:49:59Z sbolouki $
#
# This provides functions for use in tests of the reference_router system.
#
# NOTE: Many of these functions are hardware specific (e.g. LPM  and ARP table
# configuration), so beware if you use them in another system!
#
# NOTE: requires $batch and $delay to be defined in the main script.
#
# e.g.
#     use NF21RouterLib;
#     $delay = 0;
#     $batch = 0;
#
#     # use strict AFTER the $delay, $batch are declared
#     use strict;
#     # Must add this so that global vars are visible after the 'use strict'
#     use vars qw($delay $batch);
#
# To use this library in your Perl make_pkts.pl, just add the path to this
# library to your PERL5LIB environment variable, and then "use" it, as shown
# above.
#
#####################################

package NF21RouterLib ;

use Exporter;

@ISA = ('Exporter');

@EXPORT = qw(
              &enable_interrupts
              &prepare_DMA
              &resetDevice

              &cpu_rxfifo_rd_pkt

              &PCI_send_pkt
              &PCI_create_and_send_pkt

              &make_ethernet_pkt
              &make_IP_pkt
	      &make_IP_IP_pkt
              &make_RCP_pkt

              &add_LPM_table_entry
              &check_LPM_table_entry
              &invalidate_LPM_table_entry
              &get_LPM_table_entry
              &add_LPM_table_entry_generic
              &check_LPM_table_entry_generic
              &invalidate_LPM_table_entry_generic
              &get_LPM_table_entry_generic

              &add_dst_ip_filter_entry
              &invalidate_dst_ip_filter_entry
              &get_dst_ip_filter_entry
              &add_dst_ip_filter_entry_generic
              &invalidate_dst_ip_filter_entry_generic
              &get_dst_ip_filter_entry_generic

              &add_ARP_table_entry
              &invalidate_ARP_table_entry
              &get_ARP_table_entry
              &check_ARP_table_entry
              &add_ARP_table_entry_generic
              &invalidate_ARP_table_entry_generic
              &check_ARP_table_entry_generic
              &get_ARP_table_entry_generic

              &set_router_MAC
              &set_router_MAC_generic
              &get_router_MAC
              &get_router_MAC_generic

              &dotted

            );

use NF::PacketGen ('nf_PCI_read32' , 'nf_PCI_write32', 'nf_dma_data_in',
        'nf_expected_packet', 'nf_expected_dma_data', 'nf_get_sim_reg_access');

use Carp;
use strict;

# Include the reg_defines.ph header file.
#
# Sets the package to main to ensure all of the functions
# are in the main namespace. Returns to NF21RouterLib before continuing.
package main;
require "reg_defines.ph";
package NF21RouterLib;

use constant CPCI_Control_reg =>        0x0000008;
use constant CPCI_Interrupt_Mask_reg => 0x0000040;

################################################################
#
# Router setup stuff
#
################################################################
sub enable_interrupts {
  my $delay;

  if(@_) {
    $delay = shift;
  }
  else {
    $delay = $main::delay;
  }

  # Enable interrupts
  nf_PCI_write32($delay, 0, CPCI_Interrupt_Mask_reg, 0x00000000);
}

sub prepare_DMA {
  my $delay;

  if(@_) {
    $delay = shift;
  }
  else {
    $delay = $main::delay;
  }

  # Set the board to do byte-swapping on DMAs
  nf_PCI_write32($delay, 0, CPCI_Control_reg, 0x00000000);
}

sub resetDevice {
  my $delay;

  if(@_) {
    $delay = shift;
  }
  else {
    $delay = $main::delay;
  }
  nf_PCI_write32($delay, 0, CPCI_Control_reg, 0x100);
}

##############################################################################################
#
# CPU RxFIFO
#
##############################################################################################

# Get the CPU to read the specified packet from the CPU RxFIFO.
#
sub cpu_rxfifo_rd_pkt {  # src port, length, $pkt_string, $delay

  my $src_port = shift;
  die "cpu_rxfifo_rd_pkt(): src port must be in 1-4 not $src_port" unless (($src_port >0) &&($src_port<5));
  my $length = shift;
  die "cpu_rxfifo_rd_pkt(): length must be in 60-10000 not $length" unless (($length >=60) &&($length<=10000));
  my $bad = shift;
  my $pkt = shift;
  my $delay;
  if(@_) {
    $delay = shift;
  }
  else {
    $delay = $main::delay;
  }

  nf_expected_dma_data($src_port, $length, $pkt);

  printf("done pkt.\n");
}


################################################################
#
# Send a packet via the PCI bus (CPU TXFIFO)
#
################################################################

# Send a packet via the CPU TxFIFO. Create the packet and then write the
# length field (which causes it to be sent).

sub PCI_send_pkt {
  my $port = shift;
  my $pkt = shift;   # string of hex

  die "Bad port $port : must be in 1..4" if (($port < 1) or ($port > 4));

  my @data = split ' ',$pkt;
  my $length = @data+0;

  nf_dma_data_in($length, $main::delay, $port, $pkt);
}

# Create and send a packet.
sub PCI_create_and_send_pkt {
  my $port = shift;
  my $length = shift;

  die "Bad port $port : must be in 1..4" if (($port < 1) or ($port > 4));
  die "Bad length $length : must be in 60..10000" if (($length < 60) or ($length > 10000));


  my $pkt = NF::PDU->new($length);
  my @tmp = (1..$length);
  for (@tmp) { $_ %= 256 }
  $pkt->set_bytes(@tmp);

  PCI_send_pkt($port, $pkt->bytes());

  nf_expected_packet($port,  $length,  $pkt->bytes());

}






################################################################
#
# IP packet stuff
#
################################################################

# Build an IP packet with the given arguments
# Data is just sequential numbers.

sub make_RCP_pkt { # len, DA, SA, TTL, DST_IP, SRC_IP, @RCP

  my ($len, $DA, $SA, $TTL, $DST_IP, $SRC_IP, @RCP) = @_;
  my ($fwd, $rev, $rtt, $proto) = @RCP;

  my $RCP_hdr = NF::RCP_hdr->new(      fwd => $fwd,
                                        rev => $rev,
                                        rtt => $rtt,
                                        proto => $proto
                                );
  my $MAC_hdr = NF::Ethernet_hdr->new(DA => $DA,
                                       SA => $SA,
                                       Ethertype => 0x800
                                      );
  my $IP_hdr = NF::IP_hdr->new(ttl => $TTL,
                                src_ip => $SRC_IP,
                                dst_ip => $DST_IP,
                                proto => 0xfe
                               );
  $IP_hdr->checksum(0);  # make sure its zero before we calculate it.
  $IP_hdr->checksum($IP_hdr->calc_checksum);

  # create packet filling.... (IP PDU)
  my $PDU = NF::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() - $RCP_hdr->length_in_bytes());
  my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes() + $RCP_hdr->length_in_bytes()+1;
  my @data = ($start_val..$len);
  for (@data) {$_ %= 100}
  $PDU->set_bytes(@data);

  # Return complete packet data
  $MAC_hdr->bytes().$IP_hdr->bytes().$RCP_hdr->bytes().$PDU->bytes();
}

sub make_IP_pkt { # len, DA, SA, TTL, DST_IP, SRC_IP

  my ($len, $DA, $SA, $TTL, $DST_IP, $SRC_IP) = @_;

  my $MAC_hdr = NF::Ethernet_hdr->new(DA => $DA,
                                       SA => $SA,
                                       Ethertype => 0x800
                                      );
  my $IP_hdr = NF::IP_hdr->new(ttl => $TTL,
                                src_ip => $SRC_IP,
                                dst_ip => $DST_IP,
				dgram_len => $len - $MAC_hdr->length_in_bytes(),
                               );
  $IP_hdr->checksum(0);  # make sure its zero before we calculate it.
  $IP_hdr->checksum($IP_hdr->calc_checksum);

  # create packet filling.... (IP PDU)
  my $PDU = NF::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() );
  my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes()+1;
  my @data = ($start_val..$len);
  for (@data) {$_ %= 100}
  $PDU->set_bytes(@data);

  # Return complete packet data
  $MAC_hdr->bytes().$IP_hdr->bytes().$PDU->bytes();
}


sub make_IP_IP_pkt { # len, DA, SA, TTL, DST_IP_TUN, SRC_IP_TUN, DST_IP, SRC_IP

  my ($len, $DA, $SA, $TTL, $DST_IP_TUN, $SRC_IP_TUN, $DST_IP, $SRC_IP) = @_;

  my $pad_length = 4;

  my $MAC_hdr = NF::Ethernet_hdr->new(DA => $DA,
                                       SA => $SA,
                                       Ethertype => 0x800
                                      );
  my $IP_hdr_tun = NF::IP_hdr->new(ttl => $TTL,
				    src_ip => $SRC_IP_TUN,
				    dst_ip => $DST_IP_TUN,
				    proto  => 0xf4,  #IP_IP encapsulation protocol
				   );

  $IP_hdr_tun->checksum(0);  # make sure its zero before we calculate it.
  $IP_hdr_tun->checksum($IP_hdr_tun->calc_checksum);

  my $IP_hdr = NF::IP_hdr->new(ttl => $TTL,
                                src_ip => $SRC_IP,
                                dst_ip => $DST_IP
                               );
  $IP_hdr->checksum(0);  # make sure its zero before we calculate it.
  $IP_hdr->checksum($IP_hdr->calc_checksum);


  # create packet filling.... (IP PDU)
  my $PDU = NF::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() - $IP_hdr_tun->length_in_bytes());
  my $start_val = $MAC_hdr->length_in_bytes() + $IP_hdr->length_in_bytes()+1;
  my @data = ($start_val..($len-$pad_length-$IP_hdr_tun->length_in_bytes));
  for (@data) {$_ %= 100}
  $PDU->set_bytes(@data);

  # Return complete packet data
  $MAC_hdr->bytes().$IP_hdr_tun->bytes()."ff ff ff ff ".$IP_hdr->bytes().$PDU->bytes();
}

sub make_ethernet_pkt { # len, DA, SA, type

  my ($len, $DA, $SA, $type) = @_;

  my $MAC_hdr = NF::Ethernet_hdr->new(DA => $DA,
                                       SA => $SA,
                                       Ethertype => $type
                                      );

  my $PDU = NF::PDU->new($len - $MAC_hdr->length_in_bytes());
  my $start_val = $MAC_hdr->length_in_bytes()+1;
  my @data = ($start_val..$len);
  for (@data) {$_ %= 100}
  $PDU->set_bytes(@data);

  # Return complete packet data
  $MAC_hdr->bytes().$PDU->bytes();
}

################################################################
#
# Setting and getting the router MAC addresses
#
################################################################
sub set_router_MAC { # port, MAC
  my @sim_reg_access = nf_get_sim_reg_access();
  set_router_MAC_generic(@_, @sim_reg_access);
}

sub get_router_MAC { # port, MAC
  my @sim_reg_access = nf_get_sim_reg_access();
  return get_router_MAC_generic(@_, @sim_reg_access);
}


################################################################
#
# LPM table stuff
#
################################################################

sub add_LPM_table_entry {  # index, IP_subnet, MASK, NEXT_hop_IP, port
  my @sim_reg_access = nf_get_sim_reg_access();
  add_LPM_table_entry_generic(@_, @sim_reg_access);
}

sub check_LPM_table_entry {  # index, IP_subnet, MASK, NEXT_hop_IP, port
  my @sim_reg_access = nf_get_sim_reg_access();
  check_LPM_table_entry_generic(@_, @sim_reg_access);
}

sub invalidate_LPM_table_entry { #table index to invalidate
  my @sim_reg_access = nf_get_sim_reg_access();
  invalidate_LPM_table_entry_generic(@_, @sim_reg_access);
}

sub get_LPM_table_entry { #table index to get
  my @sim_reg_access = nf_get_sim_reg_access();
  get_LPM_table_entry_generic(@_, @sim_reg_access);
}

################################################################
#
# Destination IP filter table stuff
#
################################################################

sub add_dst_ip_filter_entry {  # index, dest ip
  my @sim_reg_access = nf_get_sim_reg_access();
  add_dst_ip_filter_entry_generic(@_, @sim_reg_access);
}


sub invalidate_dst_ip_filter_entry { #table index to invalidate
  my @sim_reg_access = nf_get_sim_reg_access();
  invalidate_dst_ip_filter_entry_generic(@_, @sim_reg_access);
}

sub get_dst_ip_filter_entry { #index to retrieve
  my @sim_reg_access = nf_get_sim_reg_access();
  return get_dst_ip_filter_entry_generic(@_, @sim_reg_access);
}

################################################################
#
# ARP stuff
#
################################################################
sub add_ARP_table_entry {  # index, IP, MAC,
  my @sim_reg_access = nf_get_sim_reg_access();
  add_ARP_table_entry_generic(@_, @sim_reg_access);
}

sub invalidate_ARP_table_entry { #table index to invalidate
  my @sim_reg_access = nf_get_sim_reg_access();
  invalidate_ARP_table_entry_generic(@_, @sim_reg_access);
}

sub check_ARP_table_entry {  # index, IP, MAC,
  my @sim_reg_access = nf_get_sim_reg_access();
  check_ARP_table_entry_generic(@_, @sim_reg_access);
}

sub get_ARP_table_entry {  # index
  my @sim_reg_access = nf_get_sim_reg_access();
  get_ARP_table_entry_generic(@_, @sim_reg_access);
}

################################################################
#
# Misc routines
#
################################################################

sub dotted { # convert dotted decimal to 32 bit integer
  my $dot = shift;
  if ($dot =~ m/^\s*(\d+)\.(\d+)\.(\d+)\.(\d+)\s*$/) {
    my $newip = $1<<24 | $2<<16 | $3<<8 | $4;
    return $newip
  }
  else {
    die "Bad format - expected dotted decimal: $dot"
  }
}

################################################################
#
# Setting and getting the router MAC addresses - Generic function
#
################################################################
sub set_router_MAC_generic { # port, MAC, delay
  my $port = shift;
  my $mac = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "bad port number" if (($port < 1) or ($port > 4));

  my @MAC = NF::PDU::get_MAC_address($mac);

  my $mac_hi = $MAC[0]<<8 | $MAC[1];
  my $mac_lo = $MAC[2]<<24 | $MAC[3]<<16 | $MAC[4]<<8 | $MAC[5];

  $port -= 1;

  $reg_write->( @aux, (main::ROUTER_OP_LUT_MAC_0_HI_REG() + ($port*8)), $mac_hi);
  $reg_write->( @aux, (main::ROUTER_OP_LUT_MAC_0_LO_REG() + ($port*8)), $mac_lo);
}

sub get_router_MAC_generic { # port, delay
  my $port = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "bad port number" if (($port < 1) or ($port > 4));

  $port -= 1;

  my $mac_hi = $reg_read->( @aux, (main::ROUTER_OP_LUT_MAC_0_HI_REG() + ($port*8)));
  my $mac_lo = $reg_read->( @aux, (main::ROUTER_OP_LUT_MAC_0_LO_REG() + ($port*8)));

  my $mac_tmp = sprintf("%04x%08x", $mac_hi, $mac_lo);
  $mac_tmp =~ /^(..)(..)(..)(..)(..)(..)$/;

  return "$1:$2:$3:$4:$5:$6";
}


################################################################
#
# LPM table stuff
#
################################################################

sub add_LPM_table_entry_generic {  # index, IP_subnet, MASK, NEXT_hop_IP, port
  my $index = shift;
  my $IP = shift;
  my $mask = shift;
  my $next_IP = shift;
  my $next_port = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_RT_SIZE()-1) or ($next_port < 1) or ($next_port > 255));

  if ($IP =~ m/(\d+)\./) { $IP = dotted($IP) }
  if ($mask =~ m/(\d+)\./) { $mask = dotted($mask) }
  if ($next_IP =~ m/(\d+)\./) { $next_IP = dotted($next_IP) }

  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_IP_REG(), $IP);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_MASK_REG(), $mask);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_NEXT_HOP_IP_REG(), $next_IP);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_OUTPUT_PORT_REG(), $next_port);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_LUT_WR_ADDR_REG(), $index);
}

sub check_LPM_table_entry_generic {  # index, IP_subnet, MASK, NEXT_hop_IP, port
  my $index = shift;
  my $IP = shift;
  my $mask = shift;
  my $next_IP = shift;
  my $next_port = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_RT_SIZE()-1) or ($next_port < 0) or ($next_port > 255));

  if ($IP =~ m/(\d+)\./) { $IP = dotted($IP) }
  if ($mask =~ m/(\d+)\./) { $mask = dotted($mask) }
  if ($next_IP =~ m/(\d+)\./) { $next_IP = dotted($next_IP) }

  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_LUT_RD_ADDR_REG(), $index);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_RT_IP_REG(), $IP);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_RT_MASK_REG(), $mask);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_RT_NEXT_HOP_IP_REG(), $next_IP);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_RT_OUTPUT_PORT_REG(), $next_port);
}


sub invalidate_LPM_table_entry_generic { #table index to invalidate
  my $index = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_RT_SIZE()-1));
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_IP_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_MASK_REG(), 0xffffffff);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_NEXT_HOP_IP_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_OUTPUT_PORT_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_LUT_WR_ADDR_REG(), $index);
}

sub get_LPM_table_entry_generic { #table index to invalidate
  my $index = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "get_LPM_table_entry_generic: Bad data" if (($index < 0) or ($index > main::ROUTER_RT_SIZE()-1));

  $reg_write->( @aux, main::ROUTER_OP_LUT_RT_LUT_RD_ADDR_REG(), $index);
  my $ip = $reg_read->( @aux, main::ROUTER_OP_LUT_RT_IP_REG());
  my $mask = $reg_read->( @aux, main::ROUTER_OP_LUT_RT_MASK_REG());
  my $next_hop = $reg_read->( @aux, main::ROUTER_OP_LUT_RT_NEXT_HOP_IP_REG());
  my $output_port = $reg_read->( @aux, main::ROUTER_OP_LUT_RT_OUTPUT_PORT_REG());

  my $ip_str = Socket::inet_ntoa(pack('N', $ip));
  my $mask_str = Socket::inet_ntoa(pack('N', $mask));
  my $next_hop_str = Socket::inet_ntoa(pack('N', $next_hop));

  return "$ip_str-$mask_str-$next_hop_str-" . sprintf("0x%02x", $output_port);
}

################################################################
#
# Destination IP filter table stuff
#
################################################################

sub add_dst_ip_filter_entry_generic {  # index, dest ip
  my $index = shift;
  my $IP = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_DST_IP_FILTER_TABLE_DEPTH()-1));

  if ($IP =~ m/(\d+)\./) { $IP = dotted($IP) }

  $reg_write->( @aux, main::ROUTER_OP_LUT_DST_IP_FILTER_IP_REG(), $IP);
  $reg_write->( @aux, main::ROUTER_OP_LUT_DST_IP_FILTER_WR_ADDR_REG(), $index);
}


sub invalidate_dst_ip_filter_entry_generic { #table index to invalidate
  my $index = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_DST_IP_FILTER_TABLE_DEPTH()-1));
  $reg_write->( @aux, main::ROUTER_OP_LUT_DST_IP_FILTER_IP_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_DST_IP_FILTER_WR_ADDR_REG(), $index);
}

sub get_dst_ip_filter_entry_generic {  # index
  my $index = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_DST_IP_FILTER_TABLE_DEPTH()-1));

  $reg_write->( @aux, main::ROUTER_OP_LUT_DST_IP_FILTER_RD_ADDR_REG(), $index);
  return $reg_read->( @aux, main::ROUTER_OP_LUT_DST_IP_FILTER_IP_REG());
}


################################################################
#
# ARP stuff
#
################################################################
sub add_ARP_table_entry_generic {  # index, IP, MAC,
  my $index = shift;
  my $IP = shift;
  my $mac = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;


  die "add_ARP_table_entry: Bad data" if (($index < 0) or ($index > main::ROUTER_ARP_SIZE()-1));

  if ($IP =~ m/(\d+)\./) { $IP = dotted($IP) }

  my @MAC = NF::PDU::get_MAC_address($mac);

  my $mac_hi = $MAC[0]<<8 | $MAC[1];
  my $mac_lo = $MAC[2]<<24 | $MAC[3]<<16 | $MAC[4]<<8 | $MAC[5];

  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_NEXT_HOP_IP_REG(), $IP);
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_MAC_HI_REG(), $mac_hi);
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_MAC_LO_REG(), $mac_lo);
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_LUT_WR_ADDR_REG(), $index);
}

sub invalidate_ARP_table_entry_generic { #table index to invalidate
  my $index = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "Bad data" if (($index < 0) or ($index > main::ROUTER_ARP_SIZE()-1));
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_NEXT_HOP_IP_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_MAC_HI_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_MAC_LO_REG(), 0);
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_LUT_WR_ADDR_REG(), $index);
}

sub check_ARP_table_entry_generic {  # index, IP, MAC,
  my $index = shift;
  my $IP = shift;
  my $mac = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "check_ARP_table_entry: Bad data" if (($index < 0) or ($index > main::ROUTER_ARP_SIZE()-1));

  if ($IP =~ m/(\d+)\./) { $IP = dotted($IP) }

  my @MAC = NF::PDU::get_MAC_address($mac);

  my $mac_hi = $MAC[0]<<8 | $MAC[1];
  my $mac_lo = $MAC[2]<<24 | $MAC[3]<<16 | $MAC[4]<<8 | $MAC[5];

  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_LUT_RD_ADDR_REG(), $index);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_ARP_NEXT_HOP_IP_REG(), $IP);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_ARP_MAC_HI_REG(), $mac_hi);
  $reg_read_expect->( @aux, main::ROUTER_OP_LUT_ARP_MAC_LO_REG(), $mac_lo);
}

sub get_ARP_table_entry_generic {  # index
  my $index = shift;
  my $reg_write = shift;
  my $reg_read  = shift;
  my $reg_read_expect  = shift;
  my @aux = @_;

  die "get_ARP_table_entry: Bad data" if (($index < 0) or ($index > main::ROUTER_ARP_SIZE()-1));

  # Read the ARP table entry
  $reg_write->( @aux, main::ROUTER_OP_LUT_ARP_LUT_RD_ADDR_REG(), $index);
  my $IP = $reg_read->( @aux, main::ROUTER_OP_LUT_ARP_NEXT_HOP_IP_REG());
  my $mac_hi = $reg_read->( @aux, main::ROUTER_OP_LUT_ARP_MAC_HI_REG());
  my $mac_lo = $reg_read->( @aux, main::ROUTER_OP_LUT_ARP_MAC_LO_REG());

  my $IPstr = Socket::inet_ntoa(pack('N', $IP));
  my $mac_tmp = sprintf("%04x%08x", $mac_hi, $mac_lo);
  $mac_tmp =~ /^(..)(..)(..)(..)(..)(..)$/;
  my $mac_str = "$1:$2:$3:$4:$5:$6";

  return "$IPstr-$mac_str";
}

1;

