# Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT          = 0x00  # default
IP_TOS_LOWDELAY         = 0x10  # low delay
IP_TOS_THROUGHPUT       = 0x08  # high throughput
IP_TOS_RELIABILITY      = 0x04  # high reliability
IP_TOS_LOWCOST          = 0x02  # low monetary cost - XXX
IP_TOS_ECT              = 0x02  # ECN-capable transport
IP_TOS_CE               = 0x01  # congestion experienced

# IP precedence (high 3 bits of ip_tos), hopefully unused
IP_TOS_PREC_ROUTINE             = 0x00
IP_TOS_PREC_PRIORITY            = 0x20
IP_TOS_PREC_IMMEDIATE           = 0x40
IP_TOS_PREC_FLASH               = 0x60
IP_TOS_PREC_FLASHOVERRIDE       = 0x80
IP_TOS_PREC_CRITIC_ECP          = 0xa0
IP_TOS_PREC_INTERNETCONTROL     = 0xc0
IP_TOS_PREC_NETCONTROL          = 0xe0

# Fragmentation flags (ip_off)
IP_RF           = 0x8000        # reserved
IP_DF           = 0x4000        # don't fragment
IP_MF           = 0x2000        # more fragments (not last frag)
IP_OFFMASK      = 0x1fff        # mask for fragment offset

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT  = 64            # default ttl, RFC 1122, RFC 1340
IP_TTL_MAX      = 255           # maximum ttl
# Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT          = 0x00  # default
IP_TOS_LOWDELAY         = 0x10  # low delay
IP_TOS_THROUGHPUT       = 0x08  # high throughput
IP_TOS_RELIABILITY      = 0x04  # high reliability
IP_TOS_LOWCOST          = 0x02  # low monetary cost - XXX
IP_TOS_ECT              = 0x02  # ECN-capable transport
IP_TOS_CE               = 0x01  # congestion experienced

# IP precedence (high 3 bits of ip_tos), hopefully unused
IP_TOS_PREC_ROUTINE             = 0x00
IP_TOS_PREC_PRIORITY            = 0x20
IP_TOS_PREC_IMMEDIATE           = 0x40
IP_TOS_PREC_FLASH               = 0x60
IP_TOS_PREC_FLASHOVERRIDE       = 0x80
IP_TOS_PREC_CRITIC_ECP          = 0xa0
IP_TOS_PREC_INTERNETCONTROL     = 0xc0
IP_TOS_PREC_NETCONTROL          = 0xe0

# Fragmentation flags (ip_off)
IP_RF           = 0x8000        # reserved
IP_DF           = 0x4000        # don't fragment
IP_MF           = 0x2000        # more fragments (not last frag)
IP_OFFMASK      = 0x1fff        # mask for fragment offset

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT  = 64            # default ttl, RFC 1122, RFC 1340
IP_TTL_MAX      = 255           # maximum ttl

# Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
IP_PROTO_IP             = 0             # dummy for IP
IP_PROTO_HOPOPTS        = IP_PROTO_IP   # IPv6 hop-by-hop options
IP_PROTO_ICMP           = 1             # ICMP
IP_PROTO_IGMP           = 2             # IGMP
IP_PROTO_GGP            = 3             # gateway-gateway protocol
IP_PROTO_IPIP           = 4             # IP in IP
IP_PROTO_ST             = 5             # ST datagram mode
IP_PROTO_TCP            = 6             # TCP
IP_PROTO_CBT            = 7             # CBT
IP_PROTO_EGP            = 8             # exterior gateway protocol
IP_PROTO_IGP            = 9             # interior gateway protocol
IP_PROTO_BBNRCC         = 10            # BBN RCC monitoring
IP_PROTO_NVP            = 11            # Network Voice Protocol
IP_PROTO_PUP            = 12            # PARC universal packet
IP_PROTO_ARGUS          = 13            # ARGUS
IP_PROTO_EMCON          = 14            # EMCON
IP_PROTO_XNET           = 15            # Cross Net Debugger
IP_PROTO_CHAOS          = 16            # Chaos
IP_PROTO_UDP            = 17            # UDP
IP_PROTO_MUX            = 18            # multiplexing
IP_PROTO_DCNMEAS        = 19            # DCN measurement
IP_PROTO_HMP            = 20            # Host Monitoring Protocol
IP_PROTO_PRM            = 21            # Packet Radio Measurement
IP_PROTO_IDP            = 22            # Xerox NS IDP
IP_PROTO_TRUNK1         = 23            # Trunk-1
IP_PROTO_TRUNK2         = 24            # Trunk-2
IP_PROTO_LEAF1          = 25            # Leaf-1
IP_PROTO_LEAF2          = 26            # Leaf-2
IP_PROTO_RDP            = 27            # "Reliable Datagram" proto
IP_PROTO_IRTP           = 28            # Inet Reliable Transaction
IP_PROTO_TP             = 29            # ISO TP class 4
IP_PROTO_NETBLT         = 30            # Bulk Data Transfer
IP_PROTO_MFPNSP         = 31            # MFE Network Services
IP_PROTO_MERITINP       = 32            # Merit Internodal Protocol
IP_PROTO_SEP            = 33            # Sequential Exchange proto
IP_PROTO_3PC            = 34            # Third Party Connect proto
IP_PROTO_IDPR           = 35            # Interdomain Policy Route
IP_PROTO_XTP            = 36            # Xpress Transfer Protocol
IP_PROTO_DDP            = 37            # Datagram Delivery Proto
IP_PROTO_CMTP           = 38            # IDPR Ctrl Message Trans
IP_PROTO_TPPP           = 39            # TP++ Transport Protocol
IP_PROTO_IL             = 40            # IL Transport Protocol
IP_PROTO_IP6            = 41            # IPv6
IP_PROTO_SDRP           = 42            # Source Demand Routing
IP_PROTO_ROUTING        = 43            # IPv6 routing header
IP_PROTO_FRAGMENT       = 44            # IPv6 fragmentation header
IP_PROTO_IDRP	        = 45            # Inter-Domain Routing Protocol            [Hares]
IP_PROTO_RSVP           = 46            # Reservation protocol
IP_PROTO_GRE            = 47            # General Routing Encap
IP_PROTO_MHRP           = 48            # Mobile Host Routing
IP_PROTO_ENA            = 49            # ENA
IP_PROTO_ESP            = 50            # Encap Security Payload
IP_PROTO_AH             = 51            # Authentication Header
IP_PROTO_INLSP          = 52            # Integated Net Layer Sec
IP_PROTO_SWIPE          = 53            # SWIPE
IP_PROTO_NARP           = 54            # NBMA Address Resolution
IP_PROTO_MOBILE         = 55            # Mobile IP, RFC 2004
IP_PROTO_TLSP           = 56            # Transport Layer Security
IP_PROTO_SKIP           = 57            # SKIP
IP_PROTO_ICMP6          = 58            # ICMP for IPv6
IP_PROTO_NONE           = 59            # IPv6 no next header
IP_PROTO_DSTOPTS        = 60            # IPv6 destination options
IP_PROTO_ANYHOST        = 61            # any host internal proto
IP_PROTO_CFTP           = 62            # CFTP
IP_PROTO_ANYNET         = 63            # any local network
IP_PROTO_EXPAK          = 64            # SATNET and Backroom EXPAK
IP_PROTO_KRYPTOLAN      = 65            # Kryptolan
IP_PROTO_RVD            = 66            # MIT Remote Virtual Disk
IP_PROTO_IPPC           = 67            # Inet Pluribus Packet Core
IP_PROTO_DISTFS         = 68            # any distributed fs
IP_PROTO_SATMON         = 69            # SATNET Monitoring
IP_PROTO_VISA           = 70            # VISA Protocol
IP_PROTO_IPCV           = 71            # Inet Packet Core Utility
IP_PROTO_CPNX           = 72            # Comp Proto Net Executive
IP_PROTO_CPHB           = 73            # Comp Protocol Heart Beat
IP_PROTO_WSN            = 74            # Wang Span Network
IP_PROTO_PVP            = 75            # Packet Video Protocol
IP_PROTO_BRSATMON       = 76            # Backroom SATNET Monitor
IP_PROTO_SUNND          = 77            # SUN ND Protocol
IP_PROTO_WBMON          = 78            # WIDEBAND Monitoring
IP_PROTO_WBEXPAK        = 79            # WIDEBAND EXPAK
IP_PROTO_EON            = 80            # ISO CNLP
IP_PROTO_VMTP           = 81            # Versatile Msg Transport
IP_PROTO_SVMTP          = 82            # Secure VMTP
IP_PROTO_VINES          = 83            # VINES
IP_PROTO_TTP            = 84            # TTP
IP_PROTO_NSFIGP         = 85            # NSFNET-IGP
IP_PROTO_DGP            = 86            # Dissimilar Gateway Proto
IP_PROTO_TCF            = 87            # TCF
IP_PROTO_EIGRP          = 88            # EIGRP
IP_PROTO_OSPF           = 89            # Open Shortest Path First
IP_PROTO_SPRITERPC      = 90            # Sprite RPC Protocol
IP_PROTO_LARP           = 91            # Locus Address Resolution
IP_PROTO_MTP            = 92            # Multicast Transport Proto
IP_PROTO_AX25           = 93            # AX.25 Frames
IP_PROTO_IPIPENCAP      = 94            # yet-another IP encap
IP_PROTO_MICP           = 95            # Mobile Internet Ctrl
IP_PROTO_SCCSP          = 96            # Semaphore Comm Sec Proto
IP_PROTO_ETHERIP        = 97            # Ethernet in IPv4
IP_PROTO_ENCAP          = 98            # encapsulation header
IP_PROTO_ANYENC         = 99            # private encryption scheme
IP_PROTO_GMTP           = 100           # GMTP
IP_PROTO_IFMP           = 101           # Ipsilon Flow Mgmt Proto
IP_PROTO_PNNI           = 102           # PNNI over IP
IP_PROTO_PIM            = 103           # Protocol Indep Multicast
IP_PROTO_ARIS           = 104           # ARIS
IP_PROTO_SCPS           = 105           # SCPS
IP_PROTO_QNX            = 106           # QNX
IP_PROTO_AN             = 107           # Active Networks
IP_PROTO_IPCOMP         = 108           # IP Payload Compression
IP_PROTO_SNP            = 109           # Sitara Networks Protocol
IP_PROTO_COMPAQPEER     = 110           # Compaq Peer Protocol
IP_PROTO_IPXIP          = 111           # IPX in IP
IP_PROTO_VRRP           = 112           # Virtual Router Redundancy
IP_PROTO_PGM            = 113           # PGM Reliable Transport
IP_PROTO_ANY0HOP        = 114           # 0-hop protocol
IP_PROTO_L2TP           = 115           # Layer 2 Tunneling Proto
IP_PROTO_DDX            = 116           # D-II Data Exchange (DDX)
IP_PROTO_IATP           = 117           # Interactive Agent Xfer
IP_PROTO_STP            = 118           # Schedule Transfer Proto
IP_PROTO_SRP            = 119           # SpectraLink Radio Proto
IP_PROTO_UTI            = 120           # UTI
IP_PROTO_SMP            = 121           # Simple Message Protocol
IP_PROTO_SM             = 122           # SM
IP_PROTO_PTP            = 123           # Performance Transparency
IP_PROTO_ISIS           = 124           # ISIS over IPv4
IP_PROTO_FIRE           = 125           # FIRE
IP_PROTO_CRTP           = 126           # Combat Radio Transport
IP_PROTO_CRUDP          = 127           # Combat Radio UDP
IP_PROTO_SSCOPMCE       = 128           # SSCOPMCE
IP_PROTO_IPLT           = 129           # IPLT
IP_PROTO_SPS            = 130           # Secure Packet Shield
IP_PROTO_PIPE           = 131           # Private IP Encap in IP
IP_PROTO_SCTP           = 132           # Stream Ctrl Transmission
IP_PROTO_FC             = 133           # Fibre Channel
IP_PROTO_RSVPIGN        = 134           # RSVP-E2E-IGNORE
IP_PROTO_Mobility_Header = 135         #Mobility Header                        
IP_PROTO_UDPLite        =136                 #UDPLite                                
IP_PROTO_MPLS_in_IP      =137              #MPLS-in-IP                             
IP_PROTO_MANET          =138                   #MANET                                  
IP_PROTO_HIP             =139                     #HIP                                    
IP_PROTO_Shim6          =140                  #Shim6                                  
IP_PROTO_WESP            =141                    #WESP                                   
IP_PROTO_ROHC            =142                   #ROHC                                   
IP_PROTO_RAW            = 255           # Raw IP packets
IP_PROTO_RESERVED       = IP_PROTO_RAW  # Reserved
IP_PROTO_MAX            = 255

ip_protocols = {
	IP_PROTO_IP              : 'HOPOPT',                  #dummy for IP                           
	IP_PROTO_HOPOPTS         : 'HOPOPT',                  #IPv6 hop-by-hop options                
	IP_PROTO_ICMP            : 'ICMP',                    #IPv6 hop-by-hop options                
	IP_PROTO_IGMP            : 'IGMP',                    #ICMP                                   
	IP_PROTO_GGP             : 'GGP',                     #IGMP                                   
	IP_PROTO_IPIP            : 'IPv4',                    #IP in IP                               
	IP_PROTO_ST              : 'ST',                      #ST datagram mode                       
	IP_PROTO_TCP             : 'TCP',                     #TCP                                    
	IP_PROTO_CBT             : 'CBT',                     #CBT                                    
	IP_PROTO_EGP             : 'EGP',                     #exterior gateway protocol              
	IP_PROTO_IGP             : 'IGP',                     #interior gateway protocol              
	IP_PROTO_BBNRCC          : 'BBN-RCC-MON',             #BBN RCC monitoring                     
	IP_PROTO_NVP             : 'NVP-II',                  #Network Voice Protocol                 
	IP_PROTO_PUP             : 'PUP',                     #PARC universal packet                  
	IP_PROTO_ARGUS           : 'ARGUS',                   #ARGUS                                  
	IP_PROTO_EMCON           : 'EMCON',                   #EMCON                                  
	IP_PROTO_XNET            : 'XNET',                    #Cross Net Debugger                     
	IP_PROTO_CHAOS           : 'CHAOS',                   #Chaos                                  
	IP_PROTO_UDP             : 'UDP',                     #UDP                                    
	IP_PROTO_MUX             : 'MUX',                     #multiplexing                           
	IP_PROTO_DCNMEAS         : 'DCN-MEAS',                #DCN measurement                        
	IP_PROTO_HMP             : 'HMP',                     #Host Monitoring Protocol               
	IP_PROTO_PRM             : 'PRM',                     #Packet Radio Measurement               
	IP_PROTO_IDP             : 'XNS-IDP',                 #Xerox NS IDP                           
	IP_PROTO_TRUNK1          : 'TRUNK-1',                 #Trunk-1                                
	IP_PROTO_TRUNK2          : 'TRUNK-2',                 #Trunk-2                                
	IP_PROTO_LEAF1           : 'LEAF-1',                  #Leaf-1                                 
	IP_PROTO_LEAF2           : 'LEAF-2',                  #Leaf-2                                 
	IP_PROTO_RDP             : 'RDP',                     #Reliable Datagram proto                
	IP_PROTO_IRTP            : 'IRTP',                    #Inet Reliable Transaction              
	IP_PROTO_TP              : 'ISO-TP4',                 #ISO TP class 4                         
	IP_PROTO_NETBLT          : 'NETBLT',                  #Bulk Data Transfer                     
	IP_PROTO_MFPNSP          : 'MFE-NSP',                 #MFE Network Services                   
	IP_PROTO_MERITINP        : 'MERIT-INP',               #Merit Internodal Protocol              
	IP_PROTO_SEP             : 'DCCP',                    #Sequential Exchange proto              
	IP_PROTO_3PC             : '3PC',                     #Third Party Connect proto              
	IP_PROTO_IDPR            : 'IDPR',                    #Interdomain Policy Route               
	IP_PROTO_XTP             : 'XTP',                     #Xpress Transfer Protocol               
	IP_PROTO_DDP             : 'DDP',                     #Datagram Delivery Proto                
	IP_PROTO_CMTP            : 'IDPR-CMTP',               #IDPR Ctrl Message Trans                
	IP_PROTO_TPPP            : 'TP++',                    #TP++ Transport Protocol                
	IP_PROTO_IL              : 'IL',                      #IL Transport Protocol                  
	IP_PROTO_IP6             : 'IPv6',                    #IPv6                                   
	IP_PROTO_SDRP            : 'SDRP',                    #Source Demand Routing                  
	IP_PROTO_ROUTING         : 'IPv6-Route',              #IPv6 routing header                    
	IP_PROTO_FRAGMENT        : 'IPv6-Frag',               #IPv6 fragmentation header              
	IP_PROTO_IDRP            : 'IDRP',                    #Inter-Domain Routing Protocol  [Hares] 
	IP_PROTO_RSVP            : 'RSVP',                    #Reservation protocol                   
	IP_PROTO_GRE             : 'GRE',                     #General Routing Encap                  
	IP_PROTO_MHRP            : 'DSR',                     #Mobile Host Routing                    
	IP_PROTO_ENA             : 'BNA',                     #ENA                                    
	IP_PROTO_ESP             : 'ESP',                     #Encap Security Payload                 
	IP_PROTO_AH              : 'AH',                      #Authentication Header                  
	IP_PROTO_INLSP           : 'I-NLSP',                  #Integated Net Layer Sec                
	IP_PROTO_SWIPE           : 'SWIPE',                   #SWIPE                                  
	IP_PROTO_NARP            : 'NARP',                    #NBMA Address Resolution                
	IP_PROTO_MOBILE          : 'MOBILE',                  #Mobile IP, RFC 2004                    
	IP_PROTO_TLSP            : 'TLSP',                    #Transport Layer Security               
	IP_PROTO_SKIP            : 'SKIP',                    #SKIP                                   
	IP_PROTO_ICMP6           : 'IPv6-ICMP',               #IPv6 ICMP                     
	IP_PROTO_NONE            : 'IPv6-NoNxt',              #IPv6 no next header                    
	IP_PROTO_DSTOPTS         : 'IPv6-Opts',               #IPv6 destination options               
	IP_PROTO_ANYHOST         : 'ANYHOST',                 #any host internal proto                
	IP_PROTO_CFTP            : 'CFTP',                    #CFTP                                   
	IP_PROTO_ANYNET          : 'ANYNET',                  #any local network                      
	IP_PROTO_EXPAK           : 'SAT-EXPAK',               #SATNET and Backroom EXPAK              
	IP_PROTO_KRYPTOLAN       : 'KRYPTOLAN',               #Kryptolan                              
	IP_PROTO_RVD             : 'RVD',                     #MIT Remote Virtual Disk                
	IP_PROTO_IPPC            : 'IPPC',                    #Inet Pluribus Packet Core              
	IP_PROTO_DISTFS          : 'DISTFS',                  #any distributed fs                     
	IP_PROTO_SATMON          : 'SAT-MON',                 #SATNET Monitoring                      
	IP_PROTO_VISA            : 'VISA',                    #VISA Protocol                          
	IP_PROTO_IPCV            : 'IPCV',                    #Inet Packet Core Utility               
	IP_PROTO_CPNX            : 'CPNX',                    #Comp Proto Net Executive               
	IP_PROTO_CPHB            : 'CPHB',                    #Comp Protocol Heart Beat               
	IP_PROTO_WSN             : 'WSN',                     #Wang Span Network                      
	IP_PROTO_PVP             : 'PVP',                     #Packet Video Protocol                  
	IP_PROTO_BRSATMON        : 'BR-SAT-MON',              #Backroom SATNET Monitor                
	IP_PROTO_SUNND           : 'SUN-ND',                  #SUN ND Protocol                        
	IP_PROTO_WBMON           : 'WB-MON',                  #WIDEBAND Monitoring                    
	IP_PROTO_WBEXPAK         : 'WB-EXPAK',                #WIDEBAND EXPAK                         
	IP_PROTO_EON             : 'ISO-IP',                  #ISO CNLP                               
	IP_PROTO_VMTP            : 'VMTP',                    #Versatile Msg Transport                
	IP_PROTO_SVMTP           : 'SECURE-VMTP',             #Secure VMTP                            
	IP_PROTO_VINES           : 'VINES',                   #VINES                                  
	IP_PROTO_TTP             : 'TTP',                     #TTP                                    
	IP_PROTO_NSFIGP          : 'NSFNET-IGP',              #NSFNET-IGP                             
	IP_PROTO_DGP             : 'DGP',                     #Dissimilar Gateway Proto               
	IP_PROTO_TCF             : 'TCF',                     #TCF                                    
	IP_PROTO_EIGRP           : 'EIGRP',                   #EIGRP                                  
	IP_PROTO_OSPF            : 'OSPFIGP',                 #Open Shortest Path First               
	IP_PROTO_SPRITERPC       : 'Sprite-RPC',              #Sprite RPC Protocol                    
	IP_PROTO_LARP            : 'LARP',                    #Locus Address Resolution               
	IP_PROTO_MTP             : 'MTP',                     #Multicast Transport Proto              
	IP_PROTO_AX25            : 'AX.25',                   #AX.25 Frames                           
	IP_PROTO_IPIPENCAP       : 'IPIP',                    #yet-another IP encap                   
	IP_PROTO_MICP            : 'MICP',                    #Mobile Internet Ctrl                   
	IP_PROTO_SCCSP           : 'SCC-SP',                  #Semaphore Comm Sec Proto               
	IP_PROTO_ETHERIP         : 'ETHERIP',                 #Ethernet in IPv4                       
	IP_PROTO_ENCAP           : 'ENCAP',                   #encapsulation header                   
	IP_PROTO_ANYENC          : 'ANYENC',                  #Ipsilon #private encryption scheme     
	IP_PROTO_GMTP            : 'GMTP',                    #GMTP                                   
	IP_PROTO_IFMP            : 'IFMP',                    #Flow Mgmt Proto                         
	IP_PROTO_PNNI            : 'PNNI',                    #PNNI over IP                           
	IP_PROTO_PIM             : 'PIM',                     #Protocol Indep Multicast               
	IP_PROTO_ARIS            : 'ARIS',                    #ARIS                                   
	IP_PROTO_SCPS            : 'SCPS',                    #SCPS                                   
	IP_PROTO_QNX             : 'QNX',                     #QNX                                    
	IP_PROTO_AN              : 'A_N',                     #Active Networks                        
	IP_PROTO_IPCOMP          : 'IPComp',                  #IP Payload Compression                 
	IP_PROTO_SNP             : 'SNP',                     #Sitara Networks Protocol               
	IP_PROTO_COMPAQPEER      : 'Compaq-Peer',             #Compaq Peer Protocol                   
	IP_PROTO_IPXIP           : 'IPX-in-IP',               #IPX in IP                              
	IP_PROTO_VRRP            : 'VRRP',                    #Virtual Router Redundancy              
	IP_PROTO_PGM             : 'PGM',                     #PGM Reliable Transport                 
	IP_PROTO_ANY0HOP         : 'ANY0HOP',                 #0-hop protocol                         
	IP_PROTO_L2TP            : 'L2TP',                    #Layer 2 Tunneling Proto                
	IP_PROTO_DDX             : 'DDX',                     #Data Exchange (DDX)                     
	IP_PROTO_IATP            : 'IATP',                    #Interactive Agent Xfer                 
	IP_PROTO_STP             : 'STP',                     #Schedule Transfer Proto                
	IP_PROTO_SRP             : 'SRP',                     #SpectraLink Radio Proto                
	IP_PROTO_UTI             : 'UTI',                     #UTI                                    
	IP_PROTO_SMP             : 'SMP',                     #Simple Message Protocol                
	IP_PROTO_SM              : 'SM',                      #SM                                     
	IP_PROTO_PTP             : 'PTP',                     #Performance Transparency               
	IP_PROTO_ISIS            : 'ISIS',                    #ISIS over IPv4                         
	IP_PROTO_FIRE            : 'FIRE',                    #FIRE                                   
	IP_PROTO_CRTP            : 'CRTP',                    #over IPv4 #Combat Radio Transport       
	IP_PROTO_CRUDP           : 'CRUDP',                   #Combat Radio UDP                       
	IP_PROTO_SSCOPMCE        : 'SSCOPMCE',                #SSCOPMCE                               
	IP_PROTO_IPLT            : 'IPLT',                    #IPLT                                   
	IP_PROTO_SPS             : 'SPS',                     #Secure Packet Shield                   
	IP_PROTO_PIPE            : 'PIPE',                    #Private IP Encap in IP                 
	IP_PROTO_SCTP            : 'SCTP',                    #Stream Ctrl Transmission               
	IP_PROTO_FC              : 'FC',                      #Fibre Channel                          
	IP_PROTO_RSVPIGN         : 'RSVP-E2E-IGNORE',         #RSVP-E2E-IGNORE                        
	IP_PROTO_Mobility_Header : 'Mobility_Header',         #Mobility Header                        
	IP_PROTO_UDPLite         : 'UDPLite',                 #UDPLite                                
	IP_PROTO_MPLS_in_IP      : 'MPLS-in-IP',              #MPLS-in-IP                             
	IP_PROTO_MANET           : 'MANET',                   #MANET                                  
	IP_PROTO_HIP             : 'HIP',                     #HIP                                    
	IP_PROTO_Shim6           : 'Shime6',                  #Shim6                                  
	IP_PROTO_WESP            : 'WESP',                    #WESP                                   
	IP_PROTO_ROHC            : 'ROHC',                    #ROHC                                   
	IP_PROTO_RAW             : 'RAW',                     #raw                                    
	IP_PROTO_RESERVED        : 'RESERVED',                #Reserved                               
	IP_PROTO_MAX             : 'MAX',                     #Reserved   
}
ip_protocols_rev = {
	'HOPOPT'                   :    IP_PROTO_IP     ,                  #dummy for IP                           
	'HOPOPT'                   :    IP_PROTO_HOPOPTS,                  #IPv6 hop-by-hop options                
	'ICMP'                     :    IP_PROTO_ICMP ,                    #IPv6 hop-by-hop options                
	'IGMP'                     :    IP_PROTO_IGMP ,                    #ICMP                                   
	'GGP'                      :    IP_PROTO_GGP ,                     #IGMP                                   
	'IPv4'                     :    IP_PROTO_IPIP ,                    #IP in IP                               
	'ST'                       :    IP_PROTO_ST ,                      #ST datagram mode                       
	'TCP'                      :    IP_PROTO_TCP ,                     #TCP                                    
	'CBT'                      :    IP_PROTO_CBT ,                     #CBT                                    
	'EGP'                      :    IP_PROTO_EGP ,                     #exterior gateway protocol              
	'IGP'                      :    IP_PROTO_IGP ,                     #interior gateway protocol              
	'BBN-RCC-MON'              :    IP_PROTO_BBNRCC      ,             #BBN RCC monitoring                     
	'NVP-II'                   :    IP_PROTO_NVP    ,                  #Network Voice Protocol                 
	'PUP'                      :    IP_PROTO_PUP ,                     #PARC universal packet                  
	'ARGUS'                    :    IP_PROTO_ARGUS ,                   #ARGUS                                  
	'EMCON'                    :    IP_PROTO_EMCON ,                   #EMCON                                  
	'XNET'                     :    IP_PROTO_XNET ,                    #Cross Net Debugger                     
	'CHAOS'                    :    IP_PROTO_CHAOS ,                   #Chaos                                  
	'UDP'                      :    IP_PROTO_UDP ,                     #UDP                                    
	'MUX'                      :    IP_PROTO_MUX ,                     #multiplexing                           
	'DCN-MEAS'                 :    IP_PROTO_DCNMEAS  ,                #DCN measurement                        
	'HMP'                      :    IP_PROTO_HMP ,                     #Host Monitoring Protocol               
	'PRM'                      :    IP_PROTO_PRM ,                     #Packet Radio Measurement               
	'XNS-IDP'                  :    IP_PROTO_IDP     ,                 #Xerox NS IDP                           
	'TRUNK-1'                  :    IP_PROTO_TRUNK1  ,                 #Trunk-1                                
	'TRUNK-2'                  :    IP_PROTO_TRUNK2  ,                 #Trunk-2                                
	'LEAF-1'                   :    IP_PROTO_LEAF1  ,                  #Leaf-1                                 
	'LEAF-2'                   :    IP_PROTO_LEAF2  ,                  #Leaf-2                                 
	'RDP'                      :    IP_PROTO_RDP ,                     #Reliable Datagram proto                
	'IRTP'                     :    IP_PROTO_IRTP ,                    #Inet Reliable Transaction              
	'ISO-TP4'                  :    IP_PROTO_TP      ,                 #ISO TP class 4                         
	'NETBLT'                   :    IP_PROTO_NETBLT ,                  #Bulk Data Transfer                     
	'MFE-NSP'                  :    IP_PROTO_MFPNSP  ,                 #MFE Network Services                   
	'MERIT-INP'                :    IP_PROTO_MERITINP  ,               #Merit Internodal Protocol              
	'DCCP'                     :    IP_PROTO_SEP  ,                    #Sequential Exchange proto              
	'3PC'                      :    IP_PROTO_3PC ,                     #Third Party Connect proto              
	'IDPR'                     :    IP_PROTO_IDPR ,                    #Interdomain Policy Route               
	'XTP'                      :    IP_PROTO_XTP ,                     #Xpress Transfer Protocol               
	'DDP'                      :    IP_PROTO_DDP ,                     #Datagram Delivery Proto                
	'IDPR-CMTP'                :    IP_PROTO_CMTP      ,               #IDPR Ctrl Message Trans                
	'TP++'                     :    IP_PROTO_TPPP ,                    #TP++ Transport Protocol                
	'IL'                       :    IP_PROTO_IL ,                      #IL Transport Protocol                  
	'IPv6'                     :    IP_PROTO_IP6  ,                    #IPv6                                   
	'SDRP'                     :    IP_PROTO_SDRP ,                    #Source Demand Routing                  
	'IPv6-Route'               :    IP_PROTO_ROUTING    ,              #IPv6 routing header                    
	'IPv6-Frag'                :    IP_PROTO_FRAGMENT  ,               #IPv6 fragmentation header              
	'IDRP'                     :    IP_PROTO_IDRP ,                    #Inter-Domain Routing Protocol  [Hares] 
	'RSVP'                     :    IP_PROTO_RSVP ,                    #Reservation protocol                   
	'GRE'                      :    IP_PROTO_GRE ,                     #General Routing Encap                  
	'DSR'                      :    IP_PROTO_MHRP,                     #Mobile Host Routing                    
	'BNA'                      :    IP_PROTO_ENA ,                     #ENA                                    
	'ESP'                      :    IP_PROTO_ESP ,                     #Encap Security Payload                 
	'AH'                       :    IP_PROTO_AH ,                      #Authentication Header                  
	'I-NLSP'                   :    IP_PROTO_INLSP  ,                  #Integated Net Layer Sec                
	'SWIPE'                    :    IP_PROTO_SWIPE ,                   #SWIPE                                  
	'NARP'                     :    IP_PROTO_NARP ,                    #NBMA Address Resolution                
	'MOBILE'                   :    IP_PROTO_MOBILE ,                  #Mobile IP        , RFC 2004                    
	'TLSP'                     :    IP_PROTO_TLSP ,                    #Transport Layer Security               
	'SKIP'                     :    IP_PROTO_SKIP ,                    #SKIP                                   
	'IPv6-ICMP'                :    IP_PROTO_ICMP6     ,               #IPv6 ICMP                     
	'IPv6-NoNxt'               :    IP_PROTO_NONE       ,              #IPv6 no next header                    
	'IPv6-Opts'                :    IP_PROTO_DSTOPTS   ,               #IPv6 destination options               
	'ANYHOST'                  :    IP_PROTO_ANYHOST ,                 #any host internal proto                
	'CFTP'                     :    IP_PROTO_CFTP ,                    #CFTP                                   
	'ANYNET'                   :    IP_PROTO_ANYNET ,                  #any local network                      
	'SAT-EXPAK'                :    IP_PROTO_EXPAK     ,               #SATNET and Backroom EXPAK              
	'KRYPTOLAN'                :    IP_PROTO_KRYPTOLAN ,               #Kryptolan                              
	'RVD'                      :    IP_PROTO_RVD ,                     #MIT Remote Virtual Disk                
	'IPPC'                     :    IP_PROTO_IPPC ,                    #Inet Pluribus Packet Core              
	'DISTFS'                   :    IP_PROTO_DISTFS ,                  #any distributed fs                     
	'SAT-MON'                  :    IP_PROTO_SATMON  ,                 #SATNET Monitoring                      
	'VISA'                     :    IP_PROTO_VISA ,                    #VISA Protocol                          
	'IPCV'                     :    IP_PROTO_IPCV ,                    #Inet Packet Core Utility               
	'CPNX'                     :    IP_PROTO_CPNX ,                    #Comp Proto Net Executive               
	'CPHB'                     :    IP_PROTO_CPHB ,                    #Comp Protocol Heart Beat               
	'WSN'                      :    IP_PROTO_WSN ,                     #Wang Span Network                      
	'PVP'                      :    IP_PROTO_PVP ,                     #Packet Video Protocol                  
	'BR-SAT-MON'               :    IP_PROTO_BRSATMON   ,              #Backroom SATNET Monitor                
	'SUN-ND'                   :    IP_PROTO_SUNND  ,                  #SUN ND Protocol                        
	'WB-MON'                   :    IP_PROTO_WBMON  ,                  #WIDEBAND Monitoring                    
	'WB-EXPAK'                 :    IP_PROTO_WBEXPAK  ,                #WIDEBAND EXPAK                         
	'ISO-IP'                   :    IP_PROTO_EON    ,                  #ISO CNLP                               
	'VMTP'                     :    IP_PROTO_VMTP ,                    #Versatile Msg Transport                
	'SECURE-VMTP'              :    IP_PROTO_SVMTP       ,             #Secure VMTP                            
	'VINES'                    :    IP_PROTO_VINES ,                   #VINES                                  
	'TTP'                      :    IP_PROTO_TTP ,                     #TTP                                    
	'NSFNET-IGP'               :    IP_PROTO_NSFIGP     ,              #NSFNET-IGP                             
	'DGP'                      :    IP_PROTO_DGP ,                     #Dissimilar Gateway Proto               
	'TCF'                      :    IP_PROTO_TCF ,                     #TCF                                    
	'EIGRP'                    :    IP_PROTO_EIGRP ,                   #EIGRP                                  
	'OSPFIGP'                  :    IP_PROTO_OSPF    ,                 #Open Shortest Path First               
	'Sprite-RPC'               :    IP_PROTO_SPRITERPC  ,              #Sprite RPC Protocol                    
	'LARP'                     :    IP_PROTO_LARP ,                    #Locus Address Resolution               
	'MTP'                      :    IP_PROTO_MTP ,                     #Multicast Transport Proto              
	'AX.25'                    :    IP_PROTO_AX25  ,                   #AX.25 Frames                           
	'IPIP'                     :    IP_PROTO_IPIPENCAP,                #yet-another IP encap                   
	'MICP'                     :    IP_PROTO_MICP ,                    #Mobile Internet Ctrl                   
	'SCC-SP'                   :    IP_PROTO_SCCSP  ,                  #Semaphore Comm Sec Proto               
	'ETHERIP'                  :    IP_PROTO_ETHERIP ,                 #Ethernet in IPv4                       
	'ENCAP'                    :    IP_PROTO_ENCAP ,                   #encapsulation header                   
	'ANYENC'                   :    IP_PROTO_ANYENC ,                  #Ipsilon #private encryption scheme     
	'GMTP'                     :    IP_PROTO_GMTP ,                    #GMTP                                   
	'IFMP'                     :    IP_PROTO_IFMP ,                    #Flow Mgmt Proto                         
	'PNNI'                     :    IP_PROTO_PNNI ,                    #PNNI over IP                           
	'PIM'                      :    IP_PROTO_PIM ,                     #Protocol Indep Multicast               
	'ARIS'                     :    IP_PROTO_ARIS ,                    #ARIS                                   
	'SCPS'                     :    IP_PROTO_SCPS ,                    #SCPS                                   
	'QNX'                      :    IP_PROTO_QNX ,                     #QNX                                    
	'A_N'                      :    IP_PROTO_AN  ,                     #Active Networks                        
	'IPComp'                   :    IP_PROTO_IPCOMP ,                  #IP Payload Compression                 
	'SNP'                      :    IP_PROTO_SNP ,                     #Sitara Networks Protocol               
	'Compaq-Peer'              :    IP_PROTO_COMPAQPEER  ,             #Compaq Peer Protocol                   
	'IPX-in-IP'                :    IP_PROTO_IPXIP     ,               #IPX in IP                              
	'VRRP'                     :    IP_PROTO_VRRP ,                    #Virtual Router Redundancy              
	'PGM'                      :    IP_PROTO_PGM ,                     #PGM Reliable Transport                 
	'ANY0HOP'                    :    IP_PROTO_ANY0HOP,                  #0-hop protocol                         
	'L2TP'                     :    IP_PROTO_L2TP ,                    #Layer 2 Tunneling Proto                
	'DDX'                      :    IP_PROTO_DDX ,                     #Data Exchange (DDX)                     
	'IATP'                     :    IP_PROTO_IATP ,                    #Interactive Agent Xfer                 
	'STP'                      :    IP_PROTO_STP ,                     #Schedule Transfer Proto                
	'SRP'                      :    IP_PROTO_SRP ,                     #SpectraLink Radio Proto                
	'UTI'                      :    IP_PROTO_UTI ,                     #UTI                                    
	'SMP'                      :    IP_PROTO_SMP ,                     #Simple Message Protocol                
	'SM'                       :    IP_PROTO_SM ,                      #SM                                     
	'PTP'                      :    IP_PROTO_PTP ,                     #Performance Transparency               
	'ISIS'                     :    IP_PROTO_ISIS ,                    #ISIS over IPv4                         
	'FIRE'                     :    IP_PROTO_FIRE ,                    #FIRE                                   
	'CRTP'                     :    IP_PROTO_CRTP ,                    #over IPv4 #Combat Radio Transport       
	'CRUDP'                    :    IP_PROTO_CRUDP ,                   #Combat Radio UDP                       
	'SSCOPMCE'                 :    IP_PROTO_SSCOPMCE ,                #SSCOPMCE                               
	'IPLT'                     :    IP_PROTO_IPLT ,                    #IPLT                                   
	'SPS'                      :    IP_PROTO_SPS ,                     #Secure Packet Shield                   
	'PIPE'                     :    IP_PROTO_PIPE ,                    #Private IP Encap in IP                 
	'SCTP'                     :    IP_PROTO_SCTP ,                    #Stream Ctrl Transmission               
	'FC'                       :    IP_PROTO_FC ,                      #Fibre Channel                          
	'RSVP-E2E-IGNORE'          :    IP_PROTO_RSVPIGN         ,         #RSVP-E2E-IGNORE                        
	'Mobility_Header'          :    IP_PROTO_Mobility_Header ,         #Mobility Header                        
	'UDPLite'                  :    IP_PROTO_UDPLite ,                 #UDPLite                                
	'MPLS-in-IP'               :    IP_PROTO_MPLS_in_IP ,              #MPLS-in-IP                             
	'MANET'                    :    IP_PROTO_MANET ,                   #MANET                                  
	'HIP'                      :    IP_PROTO_HIP ,                     #HIP                                    
	'Shime6'                   :    IP_PROTO_Shim6  ,                  #Shim6                                  
	'WESP'                     :    IP_PROTO_WESP ,                    #WESP                                   
	'ROHC'                     :    IP_PROTO_ROHC ,                    #ROHC                                   
	'RAW'                      :    IP_PROTO_RAW ,                     #raw                                    
	'RESERVED'                 :    IP_PROTO_RESERVED ,                #Reserved                               
	'MAX'                      :    IP_PROTO_MAX ,                     #Reserved
}

import unittest



class IPTestCase(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    def testIP_protocols(self):
        for i in range(143):
            print  ("protocol no. %d is %s"%(i, ip_protocols[i]) )
            #print  ("6 is %s"%( ip_protocols[6]))
        assert 'TCP' == ip_protocols[6]
    def testIP_protocols_rev(self):
        for i in range(143):
            print  ("protocol %s is no. %d "%(ip_protocols[i], ip_protocols_rev[ip_protocols[i]]) )
        #print  ("TCP is %s"%( ip_protocols_rev['TCP']))
        assert 6 == ip_protocols_rev['TCP']
    def testIP_IPrev(self):
        for i in range(143):
            assert  ( i==ip_protocols_rev[ip_protocols[i]] )



def test_suite():
    suite = unittest.TestSuite()
    suite.addTests([unittest.makeSuite(IPTestCase)])
    return suite

if __name__ == '__main__':
    unittest.main()
