#ifndef	RTL865X_NAT_H
#define	RTL865X_NAT_H

#define FLAG_QOS_ENABLE 1

/* NAT timeout value */
#define TCP_TIMEOUT						60	 	/* 60 secs */
#define UDP_TIMEOUT					30		/* 30 secs */
#define TCP_CLOSED_FLOW				8

#define RTL865X_PROTOCOL_UDP		0
#define RTL865X_PROTOCOL_TCP		1

#define NAT_INBOUND					0x00000001
#define NAT_OUTBOUND				0x00000002
#define NAT_PRI_PROCESSED			0x00000004
#define NAT_PRI_HALF_PROCESSED		0x00000008

#define NAT_PRE_RESERVED		0x00000100
#define RESERVE_EXPIRE_TIME	3	/*uinit:seconds*/

#define NAT_INUSE(n)				( ((n)->flags&(NAT_INBOUND|NAT_OUTBOUND)) )
#define SET_NAT_FLAGS(n, v)		(n)->flags |= v
#define CLR_NAT_FLAGS(n, v)		((n)->flags &= (~v))

#define MAX_EXTPORT_TRY_CNT 8

#define	RTL_NAPT_ACCELERATION_FAIL			-1
#define	RTL_NAPT_FULL_ACCELERATION			0
#define	RTL_NAPT_OUTBOUND_ACCELERATION 	1
#define 	RTL_NAPT_INBOUND_ACCELERATION		2

#define CONFIG_RTL_INBOUND_COLLISION_AVOIDANCE
#define CONFIG_RTL_HALF_NAPT_ACCELERATION

int32 rtl865x_nat_init(void);
int32 rtl865x_nat_reinit(void);
/*
@func enum RTL_RESULT | rtl865x_addNaptConnection | Add a NAPT Flow
@parm enum RTL_NP_PROTOCOL | protocol | The protocol to add
@parm ipaddr_t | intIp | Internal IP address
@parm uint32 | intPort | Internal Port
@parm ipaddr_t | extIp | External IP address
@parm uint32 | extPort | External Port
@parm ipaddr_t | remIp | Remote IP address
@parm uint32 | remPort | Remote Port
@parm enum RTL_NP_FLAGS | flags | reserved for future used
@rvalue RTL_SUCCESS | Add success (can be ASIC-accelerated)
@rvalue RTL_SUCCESS | Add success (cannot be ASIC-accelerated)
@rvalue RTL_ERROR_PARAMETER | Error parameter is given
@rvalue RTL_EXIST | Add an existed flow
@rvalue RTL_FAILED | General failure
@comm 
	Add a NAPT Flow Entry to L4 TCP/UDP NAPT Table(1024-Entry)
@devnote
	Insert into ip_nat_setup_info() function in file net/ipv4/netfilter/ip_nat_core.c
*/
int32 rtl865x_addNaptConnection( uint32 protocol, ipaddr_t intIp, uint32 intPort,
                                                                     ipaddr_t extIp, uint32 extPort,
                                                                     ipaddr_t remIp, uint32 remPort,
                                                                     int32 flags );
/*
@func enum RTL_RESULT | rtl865x_delNaptConnection | Delete a NAPT Flow
@parm enum RTL_NP_PROTOCOL | protocol | The protocol to delete
@parm ipaddr_t | intIp | Internal IP address
@parm uint32 | intPort | Internal Port
@parm ipaddr_t | extIp | External IP address
@parm uint32 | extPort | External Port
@parm ipaddr_t | remIp | Remote IP address
@parm uint32 | remPort | Remote Port
@rvalue RTL_SUCCESS | Delete success
@rvalue RTL_NONEXIST | Delete a non-existed flow
@rvalue RTL_FAILED | General failure
@comm 
	Delete a NAPT Flow Entry of L4 TCP/UDP NAPT Table(1024-Entry)
@devnote
	Insert into ip_nat_cleanup_conntrack() function in file net/ipv4/netfilter/ip_nat_core.c
*/
int32 rtl865x_delNaptConnection( uint32 protocol, ipaddr_t intIp, uint32 intPort,
                                                                     ipaddr_t extIp, uint32 extPort,
                                                                     ipaddr_t remIp, uint32 remPort );



int32 rtl865x_naptSync( uint32 protocol, ipaddr_t intIp, uint32 intPort,
			ipaddr_t extIp, uint32 extPort,
			ipaddr_t remIp, uint32 remPort, uint32 refresh );


#if defined (CONFIG_RTL_INBOUND_COLLISION_AVOIDANCE)
int rtl865x_optimizeExtPort(unsigned short origDelta, unsigned int rangeSize, unsigned short *newDelta);

int rtl865x_getAsicNaptHashScore( uint32 protocol, ipaddr_t intIp, uint32 intPort,
					                        ipaddr_t extIp, uint32 extPort,
					                        ipaddr_t remIp, uint32 remPort, 
					                        uint32 *naptHashScore);

int32 rtl865x_preReserveConn( uint32 protocol, ipaddr_t intIp, uint32 intPort,
					                        ipaddr_t extIp, uint32 extPort,
					                        ipaddr_t remIp, uint32 remPort);

#endif
#endif

