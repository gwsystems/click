define (
	$wanIF eth0,
	$lanIF eth1,
	$lanIP 10.10.1.1,
	$queueSize 128,
	$monThresh 50,
	$blockThresh 60,
);

fromWan :: FromDevice($wanIF);
toWan :: Queue($queueSize) -> ToDevice($wanIF);
fromLan :: FromDevice($lanIF);
toLan :: Queue($queueSize) -> ToDevice($lanIF);

l3cf :: Classifier(12/0806, 12/0800, -);
l4cf :: IPClassifier(udp, tcp, -);
udp_mon :: IPRateMonitor(PACKETS, 1, $monThresh)
udp_block :: Block($blockThresh)

fromWan -> l3cf
l3cf[0] 
	-> CheckARPHeader(14) 
	-> toLan 
l3cf[1] 
	-> CheckIPHeader(14) 
	-> l4cf
	l4cf[0] 
		-> IPPrint("UDP")
		-> udp_mon
		-> udp_block[0]	
			-> IPPrint("PASS") 
			-> toLan 
		   udp_block[1] 
			-> IPPrint("BLOCK")
			-> Discard
	l4cf[1]
		-> IPPrint("TCP")
		-> toLan 
	l4cf[2]
		-> IPPrint("UNKNOWN")
		-> Discard
l3cf[2] -> Discard
 
fromLan -> toWan
