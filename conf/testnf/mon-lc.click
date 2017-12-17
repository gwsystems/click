define (
	$monThresh 50,
	$blockThresh 60,
	$smac 11:22:33:44:55:66,
	$dmac 11:22:33:44:55:65,
	$srcip 192.168.1.1,
	$dstip 10.10.1.1,
	$pktrate 100,
	$pktnum 1000000,
	$flownum 10,
	$flowsize 10,
	$pktlen 100,
);

source :: FastUDPFlows(RATE $pktrate, LIMIT $pktnum, LENGTH $pktlen, SRCETH $smac, DSTETH $dmac, SRCIP $srcip, DSTIP $dstip, FLOWS $flownum, FLOWSIZE $flowsize)
sink :: Discard

l4cf :: IPClassifier(udp, tcp, -);
udp_mon :: IPRateMonitor(PACKETS, 1, $monThresh)
udp_block :: Block($blockThresh)

source 	-> Unqueue 
       	-> CheckIPHeader(14) 
       	-> l4cf
l4cf[0] 
       	-> IPPrint("UDP")
       	-> udp_mon
	-> udp_block[0]	
	    	-> IPPrint("PASS") 
		-> sink 
	   udp_block[1] 
       		-> IPPrint("BLOCK")
		-> Discard
l4cf[1]
       	-> IPPrint("TCP")
	-> sink 
l4cf[2]
       	-> IPPrint("UNKNOWN")
	-> Discard
