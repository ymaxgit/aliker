#!/usr/bin/perl

# This script to get the GDB tracepoint RSP package and save it
# to ./gtpstart and ./gtpstop file.
# GPL
# Copyright(C) Hui Zhu (teawater@gmail.com), 2010

binmode STDIN, ":raw";
$| = 1;

$status = 0;
$circular = 0;
$var_count = 0;

while (1) {
	sysread STDIN, $c, 1 or next;
	if ($c eq '') {
		next;
	} elsif ($c eq '+' || $c eq '-') {
		$c = '';
	}

	sysread STDIN, $line, 1024 or next;
	print '+';
	$line = $c.$line;

	open(LOG, ">>./log");
	print LOG $line."\n";
	close (LOG);

	if ($status == 0) {
		if ($line eq '$?#3f') {
			print '$S05#b8';
		} elsif ($line eq '$g#67') {
			print '$00000000#80';
		} elsif ($line =~ /^\$m/ || $line =~ /^\$p/) {
			print '$00000000#80';
		} elsif ($line eq '$qTStatus#49') {
			print '$T0;tnotrun:0;tframes:0;tcreated:0;tsize:';
			print '500000;tfree:500000;circular:0;disconn:0#d1';
		} elsif ($line eq '$QTBuffer:circular:1#f9') {
			print '$OK#9a';
			$circular = 1;
		} elsif ($line eq '$QTBuffer:circular:0#f8') {
			print '$OK#9a';
			$circular = 0;
		} elsif ($line eq '$QTStop#4b') {
			print '$OK#9a';
		} elsif ($line =~ /^\$qSupported/) {
			print '$ConditionalTracepoints+;TracepointSource+#1b';
		} elsif ($line eq '$QTinit#59') {
			$status = 1;
			open(STARTFILE, ">./gtpstart");
			print STARTFILE '$QTDisconnected:1#e3'."\n";
			if ($circular) {
				print STARTFILE '$QTBuffer:circular:1#f9'."\n";
			} else {
				print STARTFILE '$QTBuffer:circular:0#f8'."\n";
			}
		} elsif ($line eq '$qTfV#81') {
			print '$8:0:1:64756d705f737461636b#f6';
		} elsif ($line eq '$qTsV#8e') {
			if ($var_count == 0) {
				print '$7:0:1:7072696e746b5f666f726d6174#9b';
			} elsif ($var_count == 1) {
				print '$6:8:1:7072696e746b5f6c6576656c#3a';
			} elsif ($var_count == 2) {
				print '$5:0:1:7072696e746b5f746d70#28';
			} elsif ($var_count == 3) {
				print '$4:0:1:6370755f6964#f3';
			} elsif ($var_count == 4) {
				print '$3:0:1:636c6f636b#e1';
			} elsif ($var_count == 5) {
				print '$2:0:1:63757272656e745f7468726561';
				print '645f696e666f#1f';
			} elsif ($var_count == 6) {
				print '$1:0:1:63757272656e745f7461736b#c7';
			} else {
				print '$l#6c';
			}
			$var_count++;
		} else {
			print '$#00';
		}
	}

	if ($status == 1) {
		print '$OK#9a';

		print STARTFILE $line."\n";

		if ($line eq '$QTStart#b3') {
			$status = 0;

			close(STARTFILE);

			open(STOPFILE, ">./gtpstop");
			print STOPFILE '$QTStop#4b'."\n";
			close(STOPFILE);
		}
	}
}
