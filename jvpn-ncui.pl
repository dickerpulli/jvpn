#!/usr/bin/perl

# Script to run ncsvc without JAVA gui and web browser

# The author has placed this work in the Public Domain, thereby relinquishing
# all copyrights. Everyone is free to use, modify, republish, sell or give away
# this work without prior consent from anybody.

# This software is provided on an "as is" basis, without warranty of any
# kind. Use at your own risk! Under no circumstances shall the author(s) or
# contributor(s) be liable for damages resulting directly or indirectly from
# the use or non-use of this software.


use strict;
use warnings;
use Term::ReadKey;
use IO::Socket::INET;
use Fcntl ':mode';
use Getopt::Long;
use HTTP::Request::Common;
use LWP::UserAgent;
use HTTP::Cookies;
use File::Copy;
use File::Temp;
use File::Path;
use POSIX;

my %Config;
my @config_files = ("./jvpn.ini", $ENV{'HOME'}."/.jvpn.ini", "/etc/jvpn/jvpn.ini");
my $config_file = '';
my $show_help = 0;
# find configuration file
foreach my $line (@config_files) {
	$config_file=$line;
	last if -e $config_file;
}
# override from command line if specified
GetOptions ("config_file=s" => \$config_file,
	"help" => \$show_help);

if($show_help) { print_help(); }
# parse configuration
&parse_config_file ($config_file, \%Config);

my $dhost=$Config{"host"};
my $dport=$Config{"port"};
my $debug=$Config{"debug"};
my $dnsprotect=$Config{"dnsprotect"};
my $script=$Config{"script"};
my $mode=$Config{"mode"};
my $workdir=$Config{"workdir"};
my $verifycert=$Config{"verifycert"};
my $tncc_pid = 0;
my $dsid=$ARGV[0];
my $dlast="";
my $dfirst="";

my $supportdir = $ENV{"HOME"}."/.juniper_networks";
my $narport_file = $supportdir."/narport.txt";

# change directory
if (defined $workdir){
	mkpath($workdir) if !-e $workdir;
	chdir($workdir);
}

my $response_body = '';
my $ua = LWP::UserAgent->new;
# on RHEL6 ssl_opts is not exists
if(defined &LWP::UserAgent::ssl_opts) {
    $ua->ssl_opts('verify_hostname' => $verifycert);
}

$ua->agent('JVPN/Linux');

# show LWP traffic dump if debug is enabled
if($debug){
    $ua->add_handler("request_send",  sub { shift->dump; return });
    $ua->add_handler("response_done", sub { shift->dump; return });
}

# set int handlers
$SIG{'INT'}  = \&INT_handler; # CTRL+C
$SIG{'TERM'} = \&INT_handler; # Kill process
$SIG{'HUP'} = \&INT_handler; # Terminal closed
$SIG{'PIPE'} = \&INT_handler; # Process died

# flush after every write
$| = 1;

my $md5hash = '';
my $crtfile = ''; 
my $fh; # should be global or file is unlinked

# we need to fetch certificate
if (1) {
	$fh = File::Temp->new();
	$crtfile = $fh->filename;
	<< `	SHELL`;
	echo | openssl s_client -connect ${dhost}:${dport} 2>&1 | \
	sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | \
	openssl x509 -outform der > $crtfile
	SHELL
	printf("Saved certificate to temporary file: $crtfile\n");
}

if (!-e "./ncui") {
	my $res = $ua->get ("https://$dhost:$dport/dana-cached/nc/ncLinuxApp.jar",':content_file' => './ncLinuxApp.jar');
	print "Client not exists, downloading from https://$dhost:$dport/dana-cached/nc/ncLinuxApp.jar\n";
	if ($res->is_success) {
		print "Done, extracting\n";
		system("unzip -o ncLinuxApp.jar ncsvc libncui.so && chmod +x ./ncsvc");

		if(!-e 'wrapper.c'){
		printf "wrapper.c not found in ".getcwd()."\n";
			printf "Please copy this file from jvpn distro and try again";
			exit 1;
		}
		printf "Trying to compile 'ncui'. gcc must be installed to make this possible\n";
		system("gcc -m32 -o ncui wrapper.c -ldl  -Wall >compile.log 2>&1 && chmod +x ./ncui");
		if (!-e "./ncui") {
			printf("Error: Compilation failed, please compile.log\n");
			exit 1;
		}
		else {
			printf("ncui binary compiled\n");
		}
	}
	else {
		print "Download failed, exiting\n";
		exit 1;
	}
}

my $start_t = time;

my ($socket,$client_socket);
my $data;

if (1) {
	print "Starting ncui, this should bring VPN up.\nPress CTRL+C anytime to terminate connection\n";
	my $childpid;
	local $SIG{'CHLD'} = 'IGNORE';
	my @oldlist = get_tap_interfaces();
	my $pid = fork();
	if ($pid == 0) {
		my $args = './ncui -p "" '.
			"-h $dhost ".
			"-c DSID=$dsid ".
			"-f $crtfile ".
			($debug?'-l 5 -L 5':'');
		$debug && print $args;
		#open(WRITEME, "|-", "./ncui") or die "Couldn't fork: $!\n";
		#print WRITEME $args;
		#close(WRITEME);
		exec($args);
		printf("ncui terminated\n");
		exit 0;
	}
	my $exists = kill 0, $pid;
	my $vpnint = get_new_tap_interface(\@oldlist, 20);
	if ($vpnint eq '') {
		printf("Error: new interface not found, check ncsvc logs\n");
		INT_handler();
	}
	printf("Connection established, new interface: $vpnint\n");
	if($exists && $> == 0 && $dnsprotect) {
		system("chattr +i /etc/resolv.conf");
	}
	if(defined $script && -x $script){
		print "Running user-defined script\n";
		$ENV{'EVENT'}="up";
		$ENV{'MODE'}=$mode;
		$ENV{'INTERFACE'}=$vpnint;
		system($script);
	}

	for (;;) {
	    $exists = kill SIGCHLD, $pid;
	    $debug && printf("\nChecking child: exists=$exists, $pid\n");
	    # printing RX/TX from /proc/net/dev
	    my $now = time - $start_t;
	    open STAT, "/proc/net/dev" or die $!;
	    while (<STAT>) {
	    	    if ($_ =~ m/^\s*${vpnint}:\s*(\d+)(?:\s+\d+){7}\s*(\d+)/) {
	    	    	    print "\r                                                              \r";
	    	    	    my $status = sprintf("Duration: %02d:%02d:%02d  Sent: %s\tReceived: %s", 
	    	    	    	    int($now / 3600), int(($now % 3600) / 60), int($now % 60),
	    	    	    	    format_bytes($2), format_bytes($1));
			    print $status;
			    write_status($status);
	    	    }
	    }
	    close(STAT);
	    if(!$exists) {
		INT_handler();
	    }
	    sleep 2;
	}
}

# for debugging
sub hdump {
	my $offset = 0;
	my(@array,$format);
	foreach my $data (unpack("a16"x(length($_[0])/16)."a*",$_[0])) {
		my($len)=length($data);
		if ($len == 16) {
			@array = unpack('N4', $data);
			$format="0x%08x (%05d)   %08x %08x %08x %08x   %s\n";
		} else {
			@array = unpack('C*', $data);
			$_ = sprintf "%2.2x", $_ for @array;
			push(@array, '  ') while $len++ < 16;
			$format="0x%08x (%05d)" .
				"   %s%s%s%s %s%s%s%s %s%s%s%s %s%s%s%s   %s\n";
			
		} 
		$data =~ tr/\0-\37\177-\377/./;
		printf $format,$offset,$offset,@array,$data;
		$offset += 16;
	}
}

# handle ctrl+c to logout and kill ncsvc 
sub INT_handler {
	# de-register handlers
	$SIG{'INT'} = 'DEFAULT';
	$SIG{'TERM'} = 'DEFAULT';
	$SIG{'HUP'} = 'DEFAULT';
	# re-enabling cursor
	print "\e[?25h";
	if($> == 0 && $dnsprotect) {
		system("chattr -i /etc/resolv.conf");
	}
	print "Logging out...\n";
	# do logout
	$ua -> get ("https://$dhost:$dport/dana-na/auth/logout.cgi");
	print "Killing ncsvc...\n";
	# it is suid, so best is to use own api
	system("./ncsvc -K");

	# checking if resolv.conf correctly restored
	if(-f "/etc/jnpr-nc-resolv.conf"){
	    print "restoring resolv.conf\n";
	    move("/etc/jnpr-nc-resolv.conf","/etc/resolv.conf");
	}
	if(defined $script && -x $script){
		print "Running user-defined script\n";
		$ENV{'EVENT'}="down";
		$ENV{'MODE'}=$mode;
		system($script);
	}
	if(-f "/tmp/jvpn.state"){
	    print "delete jvpn.state file\n";
	    remove("/tmp/jvpn.state");
	}
	print "Exiting\n";
	exit(0);
}

sub parse_config_file {
	my $Name,my $Value; my $Config; my $File;

	($File, $Config) = @_;
	if (!open (CONFIG, "$File")) {
		print "ERROR: Config file not found : $File\n";
		exit(1);
	}
	while (<CONFIG>) {
		my $config_line=$_;
		chomp ($config_line);         # Get rid of the trailling \n
		$config_line =~ s/^\s*//;     # Remove spaces at the start of the line
		$config_line =~ s/\s*$//;     # Remove spaces at the end of the line
		if ( ($config_line !~ /^#/) && ($config_line ne "") ){    # Ignore lines starting with # and blank lines
			($Name, $Value) = split (/=/, $config_line);          # Split each line into name value pairs
			$$Config{$Name} = $Value;                             # Create a hash of the name value pairs
		}
	}
	close(CONFIG);
}

sub tncc_start {
	my $body="";
	($body) = @_;
	my @lines = split "\n", $body;
	my %params = ();
	# read applet params from the page
	foreach my $line (@lines) {
		if ( $line =~ /NAME="([^"]+)"\s+VALUE="([^"]+)"/){
			$params{ $1 } = $2;
		}
	}
	# enable tncc debug log
	if($debug && defined($params{'Parameter0'})){
		$params{'Parameter0'} =~ s/logging=0/logging=1/;
	}
	# FIXME add some param validation
	# create directory for logs if not exists
	mkpath($supportdir."/network_connect") if !-e $supportdir."/network_connect";
	# just in case. Should we also kill all tncc.jar processes?
	unlink $narport_file;
	# users reported at least 2 different class names.
	# It is not possible to fetch it from web, because it is hardcoded in hclauncer applet
	my @jclasses = ("net.juniper.tnc.NARPlatform.linux.LinuxHttpNAR","net.juniper.tnc.HttpNAR.HttpNAR");
	my $jclass; my $found = '';
	foreach $jclass (@jclasses) {
		my $chkpath = $jclass;
		$chkpath =~ s/\./\//g;
		$chkpath.=".class";
		system("unzip -t ./tncc.jar $chkpath >/dev/null 2>&1");
		$found = $jclass if $? == 0;
		last if $? == 0;
	}
	if($found eq ""){
		print "Unable to find correct start class in the tncc.jar, please report problem to developer\n";
		exit 1;
	}
	my $pid = fork();
	if ($pid == 0) {
		my @cmd = ("java");
		push @cmd, "-classpath", "./tncc.jar";
		push @cmd, $found; # class name, could be different
		if($debug) {
			push @cmd, "log_level", 10;
		}
		else {
			push @cmd, "log_level", defined($params{'log_level'})?$params{'log_level'}:2;
		}
		push @cmd, "postRetries", defined($params{'postRetries'})?$params{'postRetries'}:6;
		push @cmd, "ivehost", defined($params{'ivehost'})?$params{'ivehost'}:$dhost;
		push @cmd, "Parameter0", defined($params{'Parameter0'})?$params{'Parameter0'}:"";
		push @cmd, "locale", defined($params{'locale'})?$params{'locale'}:"en";
		push @cmd, "home_dir", $ENV{'HOME'};
		push @cmd, "user_agent", defined($params{'HTTP_USER_AGENT'})?$params{'HTTP_USER_AGENT'}:"";
		exec(@cmd);
		exit; # should never be reached
	}
	# wait up to 10 seconds for narport.txt
	for(my $i = 0; $i < 10; $i++) {
		last if(-e $narport_file);
		sleep 1;
	}
	die("Unable to start tncc.jar process") if !-e $narport_file;
	return $pid;
}

sub retry_port {
	my $port = shift;

	my $retry = 10;
	while ( $retry-- ) {
		my $socket = IO::Socket::INET->new(
			Proto    => 'tcp',
			PeerAddr => '127.0.0.1',
			PeerPort => $port,
		);
		return $socket if $socket;
		sleep 1;
	}
	die "Error connecting to 127.0.0.1:$port : $!";
}

sub read_input {
	my $param = shift;
	my $is_passwd = 0;
	my $input = "";
	my $pkey="";
	# Print '*' instead of the real characters when "password" is provided as argument
	if (defined $param && $param eq "password") {
		$is_passwd = 1;
	}
	# Start reading the keys
	ReadMode(4); # Disable the control keys
	while(ord($pkey = ReadKey(0)) != 10)
	# This will continue until the Enter key is pressed (decimal value of 10)
	{
		# For all value of ord($key) see http://www.asciitable.com/
		if(ord($pkey) == 127 || ord($pkey) == 8) {
			# DEL/Backspace was pressed
			#   1. Remove the last char from the password
			#   2. move the cursor back by one, print a blank character, move the cursor back by one
			if (length($input)) {
				print "\b \b";
			}
			chop($input);
		} elsif(ord($pkey) < 32) {
			# Do nothing with these control characters
		} else {
			$input = $input.$pkey;
			if ($is_passwd == 1) {
				print "*";
			} else {
				print $pkey;
			}
		}
	}
	ReadMode(0); # Reset the terminal once we are done
	return $input;
}

sub print_help {
	print "Usage: $0 [--config <filename>] [-h]\n".
		"\t-c, --config         configuration file, default jvpn.ini\n".
		"\t-h, --help           print this text\n".
		"Report jvpn bugs to samm\@os2.kiev.ua\n";
	exit 0;
}

# i don`t want CPAN hell
sub format_bytes
{
	my ($size) = @_;

	if ($size > 1099511627776)  #   TiB: 1024 GiB
	{
		return sprintf("%.2f TiB", $size / 1099511627776);
	}
	elsif ($size > 1073741824)  #   GiB: 1024 MiB
	{
		return sprintf("%.2f GiB", $size / 1073741824);
	}
	elsif ($size > 1048576)     #   MiB: 1024 KiB
	{
		return sprintf("%.2f MiB", $size / 1048576);
	}
	elsif ($size > 1024)        #   KiB: 1024 B
	{
		return sprintf("%.2f KiB", $size / 1024);
	}
	else                        #   B
	{
		return sprintf("%.2f B", $size);
	}
}

sub get_tap_interfaces
{
	my @intlist;
	open FILE, "/proc/net/dev" or die $!; 
	while (my $line = <FILE>){
		if($line =~ /^\s*(tun[0-9]+):/) {
			push(@intlist, $1);
		}
	}
	return @intlist;
}

sub get_new_tap_interface
{
	my (@newints, $i);
	my ($oldint, $timeout) = @_;
	for($i = 0; $i < $timeout; $i++) {
		@newints = get_tap_interfaces();
		foreach my $tunint (@newints) {
			if ( !grep { $_ eq $tunint} @$oldint ) {
				return $tunint;
			}
		}
		sleep(1);
	}
	return '';
}

sub write_status
{
    my ($status) = @_;
    my $filename = '/tmp/jvpn.state';
    open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
    print $fh $status;
    close $fh;
}
