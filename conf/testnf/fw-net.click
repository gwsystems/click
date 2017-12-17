define (
	$wanIF eth0,
	$lanIF eth1,
	$lanIP 10.10.1.1,
	$queueSize 128,
);

fromWan :: FromDevice($wanIF);
toWan :: Queue($queueSize) -> ToDevice($wanIF);
fromLan :: FromDevice($lanIF);
toLan :: Queue($queueSize) -> ToDevice($lanIF);

classifier :: Classifier (
		12/0806, //ARP Packets
		12/0800, //IP Packets
		-	 //Other
);

fw :: IPFilter (
	allow dst host $lanIP,
);

fromWan -> classifier
classifier[0] -> CheckARPHeader(14) -> toLan 
classifier[1] -> CheckIPHeader(14) 
	      -> fw 
       	      -> IPPrint("Allow", LENGTH true)
	      -> toLan
classifier[2] -> Discard

fromLan -> toWan
