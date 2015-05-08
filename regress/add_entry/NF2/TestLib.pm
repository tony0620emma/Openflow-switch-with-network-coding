#############################################################
# vim:set shiftwidth=2 softtabstop=2 expandtab:
# $Id: TestLib.pm 3904 2008-06-05 23:31:36Z brandonh $
#
#
# NetFPGA test library for sending/receiving packets
#
#
# Invoke using: use NF::TestLib
#
# Module provides NF2-specific functions
#
# Revisions:
#
##############################################################

use Test::TestLib;

package NF::TestLib;

use strict;
use Exporter;

use Test::TestLib;
use Test::Pcap;
use Test::PacketLib;

use NF21RouterLib;
use NF::RegAccess;

use threads;
use threads::shared;
use Net::RawIP;
use Getopt::Long;

use vars qw(@ISA @EXPORT);    # needed cos strict is on

@ISA    = ('Exporter');
@EXPORT = qw(
  &nftest_get_badReads
  &nftest_regwrite
  &nftest_regread
  &nftest_regread_expect
  &nftest_set_router_MAC
  &nftest_get_router_MAC
  &nftest_add_LPM_table_entry
  &nftest_check_LPM_table_entry
  &nftest_invalidate_LPM_table_entry
  &nftest_contains_LPM_table_entries
  &nftest_add_dst_ip_filter_entry
  &nftest_contains_dst_ip_filter_entries
  &nftest_invalidate_dst_ip_filter_entry
  &nftest_add_ARP_table_entry
  &nftest_invalidate_ARP_table_entry
  &nftest_check_ARP_table_entry
  &nftest_contains_ARP_table_entries

  &nftest_fpga_reset
  &nftest_phy_loopback
  &nftest_phy_reset
  &nftest_reset_phy
);

# badReads[x]=(ifname,
#              address,
#              expected_value,
#              found_value)
my @badReads;

use constant CPCI_Control_reg => 0x008;

###############################################################
# Name: nftest_get_hw_reg_access
#
# Used to access NF21RouterLib generic functions
# returns (\&nftest_regwrite, \&nftest_regread,
#          \&nftest_regread_expect, device)
#
# Arguments: device
#
###############################################################
sub nftest_get_hw_reg_access {
	my $ifaceName = shift;
	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Interface $ifaceName is not known\n"
	  unless defined $ifaceNameMap{$ifaceName};
	return ( \&nftest_regwrite, \&nftest_regread, \&nftest_regread_expect, $ifaceName );
}

###############################################################
# Name: nftest_get_badReads
# Subroutine to access failed reads list
# Arguments: none
# Returns  : @badReads which is a list of lists
#                      badReads[x]=(ifname,
#                                   address,
#                                   expected_value,
#                                   found_value)
###############################################################
sub nftest_get_badReads {
	return @badReads;
}

###############################################################
# Name: nftest_regwrite
# writes a register to the netfpga
# Arguments: ifaceName string
#            address   uint32
#            value     uint32
# Return:
###############################################################
sub nftest_regwrite {
	my $ifaceName = shift;
	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Interface $ifaceName is not known\n"
	  unless defined $ifaceNameMap{$ifaceName};
	nf_regwrite( $ifaceNameMap{$ifaceName}, @_ );
}

###############################################################
# Name: nftest_regread
#
# reads a register from the NetFPGA and returns the value
#
# Arguments: ifaceName string
#            address   uint32
#
# Return:    value     uint32
###############################################################
sub nftest_regread {
	my $dev = shift;
	my %ifaceNameMap = nftest_get_iface_name_map();
	return nf_regread( $ifaceNameMap{$dev}, @_ );
}

###############################################################
# Name: nftest_regread_expect
#
# reads a register from the NetFPGA and compares it to
# given value
#
# Arguments: ifaceName string
#            address   uint32
#            exp_value uint32
#            mask      uint32  (optional. 0 specifies don't cares)
#
# Return:    value     boolean
###############################################################
sub nftest_regread_expect {
	my $device = shift;
	my $addr   = shift;
	my $exp    = shift;
	my $mask   = shift;

	$mask = 0xffffffff unless defined $mask;

	my %ifaceNameMap = nftest_get_iface_name_map();
	my $val = nf_regread( $ifaceNameMap{$device}, $addr );

	if ( ( $val & $mask ) != ( $exp & $mask ) ) {
		printf "ERROR: Register read expected $exp (0x%08x) ", $exp;
		printf "but found $val (0x%08x) at address 0x%08x\n", $val, $addr;
		push @badReads, [ $device, $addr, $exp, $val ];
	}

	return $val;
}

################################################################
# Name: nftest_set_router_MAC
#
# Sets the MAC of a port
#
# Arguments: ifaceName string
#            MAC       string in format xx:xx:xx:xx:xx:xx
#
# Return:
################################################################
sub nftest_set_router_MAC {
	my $ifaceName = shift;
	my $portNum   = $ifaceName;

	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Couldn't find interface $ifaceName.\n" unless defined $ifaceNameMap{$ifaceName};

	die "Interface has to be an nfcX interface\n" unless ( $ifaceName =~ /^nf2c/ );
	$portNum =~ s/nf2c//;
	$portNum = ( $portNum % 4 ) + 1;
	my @reg_access = nftest_get_hw_reg_access($ifaceName);

	set_router_MAC_generic( $portNum, @_, @reg_access );
}

################################################################
# Name: nftest_get_router_MAC
#
# Gets the MAC of a port
#
# Arguments: ifaceName string
#
# Return: MAC address of interface in xx:xx:xx:xx:xx:xx format
################################################################
sub nftest_get_router_MAC {
	my $ifaceName = shift;
	my $portNum   = $ifaceName;

	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Couldn't find interface $ifaceName.\n" unless defined $ifaceNameMap{$ifaceName};

	die "Interface has to be an nfcX interface\n" unless ( $ifaceName =~ /^nf2c/ );
	$portNum =~ s/nf2c//;
	$portNum = ( $portNum % 4 ) + 1;
	my @reg_access = nftest_get_hw_reg_access($ifaceName);

	return get_router_MAC_generic( $portNum, @reg_access );
}

################################################################
# Name: nftest_add_LPM_table_entry
#
# Adds an entry to the routing table in the hardware.
#
# Arguments: ifaceName   string
#            entryIndex  int
#            subnetIP    string in format w.x.y.z
#            subnetMask  string in format w.x.y.z
#            nextHopIP   string in format w.x.y.z
#            outputPort  one-hot-encoded ports
#                        0x01 is MAC0, 0x02 is CPU0,
#                        0x04 is MAC1, 0x08 is CPU1,
#                        0x10 is MAC2, 0x20 is CPU2,
#                        0x40 is MAC3, 0x80 is CPU3,
# Return:
################################################################
sub nftest_add_LPM_table_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	add_LPM_table_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_check_LPM_table_entry
#
# Checks that the entry at the given index in the routing table
# matches the provided data
#
# Arguments: ifaceName   string
#            entryIndex  int
#            subnetIP    string in format w.x.y.z
#            subnetMask  string in format w.x.y.z
#            nextHopIP   string in format w.x.y.z
#            outputPort  one-hot-encoded ports
#                        0x01 is MAC0, 0x02 is CPU0,
#                        0x04 is MAC1, 0x08 is CPU1,
#                        0x10 is MAC2, 0x20 is CPU2,
#                        0x40 is MAC3, 0x80 is CPU3,
# Return:
################################################################
sub nftest_check_LPM_table_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	check_LPM_table_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_invalidate_LPM_table_entry
#
# clears an entry in the routing table (by setting everything
# to 0)
#
# Arguments: ifaceName   string
#            entryIndex  int
#
# Return:
################################################################
sub nftest_invalidate_LPM_table_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	invalidate_LPM_table_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_contains_LPM_table_entries
#
# Compares the expected_entries array against what is in hardware
# returning any expected_entries that do not exist in hardware
#
# Arguments: expected_entries array of entries, with each field
# separated by a hyphen ('-')
#
# Return: array of missing entries as strings
################################################################
sub nftest_contains_LPM_table_entries {
	my @reg_access       = nftest_get_hw_reg_access("nf2c0");
	my $expected_entries = shift;
	my %actual_entries;
	my @missing_entries;

	for ( 0 .. ( main::ROUTER_RT_SIZE() - 1 ) ) {
		my $entry = get_LPM_table_entry_generic( $_, @reg_access );
		$actual_entries{$entry} = $entry;
	}

	foreach my $expected_entry (@$expected_entries) {
		if ( !exists $actual_entries{$expected_entry} ) {
			push( @missing_entries, $expected_entry );
		}
	}

	return \@missing_entries;
}

################################################################
# Name: nftest_add_dst_ip_filter_entry
#
# Adds an entry in the IP destination filtering table. Any
# packets with IP dst addr that matches in this table is sent to
# the CPU. This is also used to set the IP address of the
# router's ports.
#
# Arguments: ifaceName   string
#            entryIndex  int
#            destIP      string in format w.x.y.z
# Return:
################################################################
sub nftest_add_dst_ip_filter_entry {
	my $ifaceName  = shift;
	my @reg_access = nftest_get_hw_reg_access($ifaceName);
	add_dst_ip_filter_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_add_dst_ip_filter_entry
#
# Removes an entry from the IP destination filtering table by
# setting it to 0.
#
# Arguments: ifaceName   string
#            entryIndex  int
#
# Return:
################################################################
sub nftest_invalidate_dst_ip_filter_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	invalidate_dst_ip_filter_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_contains_dst_ip_filter_entries
#
# Compares the expected_ips array against what is in hardware
# returning any expected_ips that do not exist in hardware
#
# Arguments: expected_ips array of ip address strings
#
# Return: array of missing ip address strings
################################################################
sub nftest_contains_dst_ip_filter_entries {
	my @reg_access   = nftest_get_hw_reg_access("nf2c0");
	my $expected_ips = shift;
	my %actual_ips;
	my @missing_ips;

	for ( 0 .. ( main::ROUTER_DST_IP_FILTER_TABLE_DEPTH() - 1 ) ) {
		my $ip = get_dst_ip_filter_entry_generic( $_, @reg_access );
		$actual_ips{$ip} = $ip;
	}

	foreach my $expected_ip (@$expected_ips) {
		if ( !exists $actual_ips{ dotted($expected_ip) } ) {
			push( @missing_ips, $expected_ip );
		}
	}

	return \@missing_ips;
}

################################################################
# Name: nftest_add_ARP_table_entry
#
# adds an entry to the hardware's ARP table.
#
# Arguments: ifaceName   string
#            entryIndex  int
#            nextHopIP   string in format w.x.y.z
#            nextHopMAC  string in format w.x.y.z
#
# Return:
################################################################
sub nftest_add_ARP_table_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	add_ARP_table_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_invalidate_ARP_table_entry
#
# clears an entry from the hardware's ARP table by setting to
# all zeros.
#
# Arguments: ifaceName   string
#            entryIndex  int
#
# Return:
################################################################
sub nftest_invalidate_ARP_table_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	invalidate_ARP_table_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_check_ARP_table_entry
#
# checks the entry in the hardware's ARP table.
#
# Arguments: ifaceName   string
#            entryIndex  int
#            nextHopIP   string in format w.x.y.z
#            nextHopMAC  string in format w.x.y.z
#
# Return:
################################################################
sub nftest_check_ARP_table_entry {
	my @reg_access = nftest_get_hw_reg_access(shift);
	check_ARP_table_entry_generic( @_, @reg_access );
}

################################################################
# Name: nftest_contains_ARP_table_entries
#
# Compares the expected_entries array against what is in hardware
# returning any expected_entries that do not exist in hardware
#
# Arguments: expected_entries array of entries, with each field
# separated by a hyphen ('-')
#
# Return: array of missing entries as strings
################################################################
sub nftest_contains_ARP_table_entries {
	my @reg_access       = nftest_get_hw_reg_access("nf2c0");
	my $expected_entries = shift;
	my %actual_entries;
	my @missing_entries;

	for ( 0 .. ( main::ROUTER_ARP_SIZE() - 1 ) ) {
		my $entry = get_ARP_table_entry_generic( $_, @reg_access );
		$actual_entries{$entry} = $entry;
	}

	foreach my $expected_entry (@$expected_entries) {
		if ( !exists $actual_entries{$expected_entry} ) {
			push( @missing_entries, $expected_entry );
		}
	}

	return \@missing_entries;
}

###############################################################
# Name: nftest_fpga_reset
# Resets both the Virtex and Spartan FPGAs
# Note: This resets the state of the logic but does not clear
# the FGPGAs
# Arguments: $ifaceName string containing name of interface
# Returns:
###############################################################
sub nftest_fpga_reset {
	my $ifaceName = shift;

	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Interface $ifaceName is not known\n"
	  unless defined $ifaceNameMap{$ifaceName};

	# Must write 1 into bit 8 while keeping the other values
	my $currVal = nf_regread( $ifaceNameMap{$ifaceName}, CPCI_Control_reg );
	$currVal |= 0x100;
	nf_regwrite( $ifaceNameMap{$ifaceName}, CPCI_Control_reg, $currVal );

	# Sleep for a while to allow the reset to complete
	sleep 1;
}

###############################################################
# Name: nftest_reset_phy
# resets the phy on the NetFPGA
# Arguments: $ifaceName string containing name of interface
# Returns:
###############################################################
sub nftest_reset_phy {

	my %pktHashes = nftest_get_pkt_hashes();

	# reset PHY in case it has been modified
	foreach my $ifaceName ( keys %pktHashes ) {
		if ( $ifaceName =~ /^nf2c/ ) {
			nftest_phy_reset($ifaceName);
		}
	}

	`sleep 6`;

	return;
}

###############################################################
# Name: nftest_phy_loopback
# Puts the phy in loopback mode
# Arguments: $ifaceName string containing name of interface
# Returns:
###############################################################
sub nftest_phy_loopback {
	my $ifaceName = shift;
	my $portNum   = $ifaceName;

	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Couldn't find interface $ifaceName.\n" unless defined $ifaceNameMap{$ifaceName};
	die "Interface has to be an nfcX interface\n" unless ( $ifaceName =~ /^nf2c/ );

	$portNum =~ s/nf2c//;
	$portNum = ( $portNum % 4 );

	my @addr = (
		main::MDIO_0_CONTROL_REG(), main::MDIO_1_CONTROL_REG(),
		main::MDIO_2_CONTROL_REG(), main::MDIO_3_CONTROL_REG()
	);
	nftest_regwrite( $ifaceName, $addr[$portNum], 0x5140 );
	system "usleep 10";
}

###############################################################
# Name: nftest_phy_reset
# resets the phy
# Arguments: $ifaceName string containing name of interface
# Returns:
###############################################################
sub nftest_phy_reset {
	my $ifaceName = shift;
	my $portNum   = $ifaceName;

	my %ifaceNameMap = nftest_get_iface_name_map();
	die "Couldn't find interface $ifaceName.\n" unless defined $ifaceNameMap{$ifaceName};
	die "Interface has to be an nfcX interface\n" unless ( $ifaceName =~ /^nf2c/ );

	$portNum =~ s/nf2c//;
	$portNum = ( $portNum % 4 );

	my @addr = (
		main::MDIO_0_CONTROL_REG(), main::MDIO_1_CONTROL_REG(),
		main::MDIO_2_CONTROL_REG(), main::MDIO_3_CONTROL_REG()
	);

	nftest_regwrite( $ifaceName, $addr[$portNum], 0x8000 );
	system "usleep 10";
}

1;