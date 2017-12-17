define (
	$lanIP 10.10.1.1,
	$smac 11:22:33:44:55:66,
	$dmac 11:22:33:44:55:65,
	$srcip 192.168.1.1,
	$dstip 10.10.1.1,
	$pktrate 10,
	$pktnum 10000,
	$flownum 10,
	$flowsize 10,
	$pktlen 100,
);

source :: FastTCPFlows(RATE $pktrate, LIMIT $pktnum, LENGTH $pktlen, SRCETH $smac, DSTETH $dmac, SRCIP $srcip, DSTIP $dstip, FLOWS $flownum, FLOWSIZE $flowsize)
sink :: Discard

fw :: IPFilter (
	allow dst host $lanIP,
);

source -> Unqueue 
       -> CheckIPHeader(14) 
       -> fw 
       -> IPPrint("Allow", LENGTH true)
       -> sink 
