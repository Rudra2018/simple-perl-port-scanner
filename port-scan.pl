#!/usr/bin/perl
#Simple port scanner credits-https://null-byte.wonderhowto.com/

use Socket;

$| = 1;

my ($ip,$protocol,$port,$myhouse,$yourhouse,$log);

$protocol = getprotobyname('tcp');

($ip,$port,$port_stop,$log) = @ARGV;

if($ip eq "-h"){
	&usage();
}

$ip = "localhost" if not $ip;
$port = 1 if not $port;
$port_stop = 65535 if not $port_stop;
$log = "qsopenports.txt" if not $log;

unless (open(LOG_FILE,">>$log")) {
	die "Can't open log file $log for writing: $!\n"
}

#Make file handle so the buffer is flushed after every write
select((select(LOG_FILE),$| = 1)[0]);

print LOG_FILE "The following ports are open on $ip between port $port and $port_stop\n\n";

print "Checking $ip for open ports..\n";

for(;$port<$port_stop;$port +=1){
	socket(SOCKET,PF_NET,SOCK_STREAM,$protocol);

	$yourhouse = inet_aton($ip);

	$myhouse = sockaddr_in($port,$yourhouse);

	if(!connect(SOCKET,$myhouse)) {
		printf "%d\r",$port;
	} else {
		printf "%d <- open\n",$port;
		print LOG_FILE "$port\n";
		close SOCKET || die "close: $!";
	}
}

close LOG_FILE || die "close: $!";
printf "Scan Complete.\n";
printf "Those are the open ports for:$ip\n";

sub usage() {
	print "Usage: ./port-scan [host] [start port] [stop port] [logfile]\n";
	print "Defaults to localhost and port 1 to port 6553 qsopenports.txt\n";
	exit 0;
}