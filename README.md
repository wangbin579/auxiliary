#[TCPCopy](https://github.com/wangbin579/tcpcopy) - A TCP Stream Replay Tool

TCPCopy is a TCP stream replay tool to support real testing of Internet server applications. 



##Description
Although the real live flow is important for the test of Internet server applications, it is hard to simulate it as online environments are too complex. To support more realistic testing of Internet server applications, we proposes a live flow reproduction tool – TCPCopy, which could generate the test workload that is similar to the production workload. TCPCopy consists of two components: TCPCopy Client (tcpcopy) and TCPCopy Server (intercept). TCPCopy Client (tcpcopy) is deployed on the production system and it copies live flow data, does necessary modifications and sends them to the test system in real-time. TCPCopy Server (intercept) is deployed on the test system and it returns necessary response information to TCPCopy Client (tcpcopy). To the test server, the reproduced workload is just from end-users. Currently, TCPCopy has been widely used by companies in China.   

TCPCopy has little influence on the production system except occupying additional CPU, memory and bandwidth. Moreover, the reproduced workload is similar to the production workload in request diversity, network latency and resource occupation.


##Design Goals
1. Reproduction of realistic Internet production workload
  - Traditionally, Internet server applications are often deployed online without testing with realistic Internet production workloads. Thus, developers are often not sure whether their applications could work well when deployed online. If we could introduce the online complexity (e.g., request diversity and network latencies) to the test system, we believe most problems could be found before actual deployment. 
2. Little influence on production systems
  - Generally, online production systems should not be affected. For example, online service interruptions are often unacceptable. TCPCopy aims to affect the online system as little as possible.  
3. Better use of online production workloads
  - Currently, online Internet production workloads are often unused and the intranet network bandwidth is not sufficiently utilized. It would be fascinating if TCPCopy could utilize the online production workload to support performance testing of Internet server applications. 
4. Long-term testing support
  - As some problems only appear after the system runs for a long time, it is necessary to design a tool that supports long-term testing with real Internet workload. TCPCopy will try to support such long-term testing.


##Scenarios:
* Distributed stress testing
  - Use tcpcopy to copy real-world data to stress test your server software. Bugs that only can be produced in high-stress situations can be found
* Live testing
  - Prove the new system is stable and find bugs that only occur in the real world
* Regression testing
* performance comparison
  - For instance, you can use tcpcopy to [compare the performance of Apache and Nginx](https://raw.github.com/wangbin579/auxiliary/master/docs/Apache%202.4%20vs.%20Nginx%20-%20A%20comparison%20under%20real%20online%20applications.pdf)
    


##Architecture 

There are two kinds of architectures that TCPCopy could be used depending on where to capture response packets.

###Traditional architecture
![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/traditional_tcpcopy_archicture.GIF)

Figure 1 shows the traditional architecture of TCPCopy. It consists of two components: TCPCopy Client (tcpcopy) and TCPCopy Server (intercept). TCPCopy Client is deployed on the production server. It captures the production workload, does the necessary processing (including TCP interaction simulation, network latency control, and common upper-layer interaction simulation), and transmits the reproduced workload to the test system in real-time by packet injection technique. TCPCopy Client also sends route information to TCPCopy Server, which would be used by TCPCopy Server to decide which TCPCopy Client each response information should return to. TCPCopy Server is deployed on the test server. It intercepts test server responses, extracts the response information, deals with the response packets, and sends response information back to TCPCopy Client through a special channel.  

![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/traditional_tcpcopy_usage.GIF)

Figure 2 shows the architecture of using TCPCopy to do realistic testing of Internet server applications. In the online production system, when the end-users access the online application server, the application server may visit the backend services to process users’ requests if needed and return feedbacks to end-users. Meanwhile, TCPCopy Client (tcpcopy) is deployed on the production server to copy and send the reproduced workload to the test system. In the test system, the reproduced flow accesses the test application server, which would also visit the backend services if needed and then return feedbacks. TCPCopy Server (intercept)  handles these feedbacks and returns the necessary response information to TCPCopy Client (tcpcopy). In addition, as both TCPCopy Client (tcpcopy) and TCPCopy Server (intercept) could be deployed on several servers, TCPCopy has good scalability. It could copy live flow on one or several production servers to one test server.  

###Advanced architecture

![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/advanced_tcpcopy_archicture.GIF)

As you can see, intercept runs at an independent machine which is different from test server and captues response packets at the data link layer. The only operation involved in test server is adding route commands to route response packets to the machine which runs the TCPCopy server. All these changes lead to more realistic testing because ip queue or nfqueue will not affect the test server. Also the potential of intercept is enhanced because capturing packets in data link is more powerful and multiple instances of intercept could also be supported.

![tcpcopy](https://raw.github.com/wangbin579/auxiliary/master/images/advanced_tcpcopy_usage.GIF)

Figure 4 shows the advanced architecture of using TCPCopy to do realistic testing of Internet server applications. TCPCopy server(intercept) is removed from machines which run upper-layer applications. 


It is much more complicated when using Advanced architecture, but it is more real and more powerful.


##Quick start

Two quick start options are available:

* [Download the latest release](https://github.com/wangbin579/tcpcopy/releases/tag/0.9.0).
* Clone the repo: `git clone git://github.com/wangbin579/tcpcopy.git`.


##Getting TCPCopy installed
1. cd tcpcopy
2. sh autogen.sh
3. ./configure 
  - choose appropriate configure options if needed
4. make
5. make install


###Configure Options
    --enable-debug      compile TCPCopy with debug support (saved in a log file)
    --enable-mysqlsgt   run TCPCopy at mysql skip-grant-tables mode(recommended)
    --enable-mysql      run TCPCopy at mysql mode
	--enable-offline    run TCPCopy at offline mode
	--enable-pcap       run TCPCopy at pcap mode
    --enable-udp        run TCPCopy at udp mode
	--enable-nfqueue    run the TCPCopy server (intercept) at nfqueue mode
	--enable-advanced   run TCPCopy at advanced mode (advanced archecture) 
	--enable-dlinject   send packets at data link layer instead of IP layer
    --enable-rlantency  add more lantency control

###Recommended configure

1. Recommended traditional use
  - ./configure  
2. Recommended advanced use
  - ./configure --enable-advanced --enable-pcap  
3. mysql replay with mysql in test server working in skip-grant-table mode
  - ./configure --enable-mysqlsgt  
4. offline replay  
  - ./configure --enable-offline  


##Running TCPCopy

###Traditional usage guide
    Assume "./configure" is configured

    Run:
    a) on the target host (root privilege is required):

      using ip queue (kernel < 3.5):
        modprobe ip_queue # if not running
        iptables -I OUTPUT -p tcp --sport port -j QUEUE # if not set
        ./intercept 

      or

      using nfqueue (kernel >= 3.5):
        iptables -I OUTPUT -p tcp --sport port -j NFQUEUE # if not set
        ./intercept

    b) on the source host (root privilege is required):
      sudo ./tcpcopy -x localServerPort-targetServerIP:targetServerPort


###Advanced usage guide:
	Assume "./configure --enable-advanced --enable-pcap" is configured

	Run:
	a) On the target server 1 which runs test server applications (root privilege is required):
	    Set route command appropriately to route response packets to the target server 2
        For example:
           route del default gw 61.135.233.219
           route add default gw 61.135.233.161
	    61.135.233.219 is the actual IP address which is the default gateway, while 61.135.233.161
        is the IP address of target server 2. We set these route commands to route all extenal 
        responses to the target server 2.

	b) On the target server 2 which runs intercept(TCPCopy server) (root privilege is required):
	    sudo ./intercept -F <filter> -i <device,> 
	
	c) On the online source server (root privilege is required):
	    sudo ./tcpcopy -x localServerPort-targetServerIP:targetServerPort -s <intercept server,> -i <device,> 
	  
	Note that the filter format is the same as pcap filter.
	For example:
	  ./intercept -i eth0 -F 'tcp and src port 11511' –d
	Intercept will capture response packets of tcp based application which occupies port 11511 from device eth0



###Additional commands
./tcpcopy -h or ./intercept -h for more details


##Note
1. It is tested on Linux only (kernal 2.6 or above)
2. TCPCopy may lose packets hence lose requests
3. Root privilege is required
4. TCPCopy does only support client-initiated connections now
5. TCPCopy does not support replay for server applications which use SSL/TLS



##Example using traditional architecture

Suppose there are two online hosts, 1.2.3.25 and 1.2.3.26. And 1.2.3.161 is the target host. Port 11311 is used as local server port and port 11511 is used as remote target server port. We use tcpcopy to test if 1.2.3.161 can process 2X requests than a host can serve.

Here we use traditional tcpcopy to perform the above test task.
    
    1) on the target host (1.2.3.161, kernel 2.6.18)
       # modprobe ip_queue 
       # iptables -I OUTPUT -p tcp --sport 11511 -j QUEUE 
       # ./intercept

    2) online host (1.2.3.25)
       # ./tcpcopy -x 11311-1.2.3.161:11511

    3) online host(1.2.3.26)
       # ./tcpcopy -x 11311-1.2.3.161:11511

    CPU load and memory usage is as follows:
       1.2.3.25:
           21158 appuser   15   0  271m 226m  756 S 24.2  0.9  16410:57 asyn_server
           9168  root      15   0 18436  12m  380 S  8.9  0.1  40:59.15 tcpcopy
       1.2.3.26:
           16708 appuser   15   0  268m 225m  756 S 25.8  0.9  17066:19 asyn_server
           11662 root      15   0 17048  10m  372 S  9.3  0.0  53:51.49 tcpcopy
       1.2.3.161:
           27954 root      15   0  284m  57m  828 S 58.6  1.4 409:18.94 asyn_server
           1476  root      15   0 14784  11m  308 S  7.7  0.3  49:36.93 intercept
    Access log analysis:
       1.2.3.25:
           $ wc -l access_1109_09.log
             7867867,  2185 reqs/sec
       1.2.3.26:
           $ wc -l access_1109_09.log
             7843259,  2178 reqs/sec
       1.2.3.161:
           $ wc -l access_1109_09.log
             15705229, 4362 reqs/sec
       request loss ratio:
           (7867867 + 7843259 - 15705229) / (7867867 + 7843259) = 0.0375%

Clearly, the target host can process 2X of requests a source host can serve.How is the CPU load? Well, tcpcopy on online host 1.2.3.25 used 8.9%, host 1.2.3.26 used 9.3%, while intercept on the target host consumed about 7.7%. We can see that the CPU load is low here, and so is the memory usage.



##Influential Factors
There are several factors that could influence TCPCopy, which will be introduced in detail in the following sections.

###1. Capture Interface
TCPCopy utilizes raw socket input interface by default to capture packets in the IP layer on the online server. The system kernel may lose some packets when the system is busy. Thus, the related system parameters should be set appropriately. 

If you configure --enable-pcap, then TCPCopy could capture packets in the data link layer and could also filter packets in the kernel.

###2. Send Interface
TCPCopy utilizes raw socket output interface by default to send packets in the IP layer to a target server. The system kernel may encounter problems and not send all the packets successfully. For example, when the packet size is larger than MTU, raw socket output interface would refuse to send these large packets. In TCPCopy 0.5 or above versions, with our special processing, large packets are supported. 

If you configure --enable-dlinject, then TCPCopy could send packets in the data link layer to a target server.

###3.On the Way to the Target Server 
When a packet is sent by the TCPCopy client (tcpcopy), it may encounter many challenges before reaching the target server. As the source IP address in the packet is still the end-user’s IP address other than the online server’s, some security devices may take it for an invalid or forged packet and drop it. In this case, when you use tcpdump to capture packets on the target server, no packets from the expected end-users will be captured. To know whether you are under such circumstances, you can choose a target server in the same network segment to do a test. If packets could be sent to the target server successfully in the same network segment but unsuccessfully across network segments, your packets may be dropped halfway. 

To solve this problem, we suggest deploying the TCPCopy client (tcpcopy) and the TCPCopy server (intercept) on servers in the same network segment. There’s also another solution with the help of a proxy in the same network segment. The TCPCopy client could send packets to the proxy and then the proxy would send the corresponding requests to the target server in another network segment.

Note that visiting another virtual machine in the same segment is the same as visiting a machine in anoter network segment.

####4. OS of the Target Server
The target server may set rpfilter, which would check whether the source IP address in the packet is forged. If yes, the packet will be dropped in the IP layer.

If the target server could not receive any requests although packets can be captured by tcpdump on the target server, you should check if you have any corresponding rpfilter settings. If set, you have to remove the related settings to let the packets pass through the IP layer.

There are also other possibilities that cause TCPCopy not working if you use the traditional tcpcopy, such as iptables setting problems.

###5. Applications on the Target Server
It is likely that the application on the target server could not process all the requests in time. On the one hand, bugs in the application may make the request not be responded for a long time. On the other hand, some protocols above TCP layer may only process the first request in the socket buffer and leave the remaining requests in the socket buffer unprocessed. 

###6. Netlink Socket Interface 
Note that the following problem only occursin the traditional usage when configure --disable-advanced and IP Queue is used.

Packet loss also occurs when ip queue module transfers the response packet to the TCPCopy server (intercept) under a high-pressure situation. By using command “cat /proc/net/ip_queue”, you can check the state of ip queue. 

If the value of queue dropped increases continually, ip_queue_maxlen should be set larger. For example, the following command modifies the default queue length 1024 to 4096.
 > echo 4096 > /proc/sys/net/ipv4/ip_queue_maxlen

If the value of netlink dropped increases continually, rmem_max and wmem_max should be set larger. 
Here is an example.
 >sysctl -w net.core.rmem_max=16777216  
 >sysctl -w net.core.wmem_max=16777216




##Release History
+ 2011.09  version 0.1, TCPCopy released
+ 2011.11  version 0.2, fix some bugs
+ 2011.12  version 0.3, support mysql copy 
+ 2012.04  version 0.3.5, add support for multiple copies of the source request
+ 2012.05  version 0.4, fix some bugs 
+ 2012.07  version 0.5, support large packets (>MTU)
+ 2012.08  version 0.6, support offline replaying from pcap files to the target server
+ 2012.10  version 0.6.1, support intercept at multi-threading mode
+ 2012.11  version 0.6.3, fix fast retransmitting problem
+ 2012.11  version 0.6.5, support nfqueue
+ 2013.03  version 0.7.0, support lvs
+ 2013.06  version 0.8.0, support new configure option with configure --enable-advanced and optimize intercept
+ 2013.08  version 0.9.0, pcap injection is supported and GPLv2 code has been removed for mysql replay,etc



##Bugs and feature requests
Have a bug or a feature request? [Please open a new issue](https://github.com/wangbin579/tcpcopy/issues). Before opening any issue, please search for existing issues.


## Copyright and license

Copyright 2013 under [the BSD license](LICENSE).


