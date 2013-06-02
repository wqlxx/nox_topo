/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "topology.hh"

#include <boost/bind.hpp>
#include <inttypes.h>

#include "assert.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "port-status.hh"
#include "vlog.hh"
#include "openflow-default.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;
using namespace vigil::container;

namespace vigil {
namespace applications {

static Vlog_module lg("topology");

Topology::Topology(const Context* c,
                   const json_object*)
    : Component(c)
{
    empty_dp.active = false;

        // For bebugging
        // Link_event le;
        // le.action = Link_event::ADD;
        // le.dpsrc = datapathid::from_host(0);
        // le.dpdst = datapathid::from_host(1);
        // le.sport = 0;
        // le.dport = 0;
        // add_link(le);
}

void
Topology::getInstance(const container::Context* ctxt, Topology*& t)
{
    t = dynamic_cast<Topology*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(Topology).name())));
}

void
Topology::configure(const Configuration*)
{
    register_handler<Link_event>
        (boost::bind(&Topology::handle_link_event, this, _1));
    register_handler<Datapath_join_event>
        (boost::bind(&Topology::handle_datapath_join, this, _1));
    register_handler<Datapath_leave_event>
        (boost::bind(&Topology::handle_datapath_leave, this, _1));
    register_handler<Port_status_event>
        (boost::bind(&Topology::handle_port_status, this, _1));
    register_handler<Packet_in_event>
        (boost::bind(&Topology::handle_packet_in, this, _1));
}

void
Topology::install()
{}


/************************************************/
/*modify by wangq 20130531*/

void 
Topology::set_flow_entry(const uint32_t in_port, const uint32_t out_port, const datapathid &dpid)
{
	VLOG_INFO(lg,"set_flow_entry | topology size is %d",topology.size());	
    VLOG_INFO(lg,"set_flow_entry | this is set_flow_entry | now we begin to set flow entry to switch");

	for(uint32_t i=2;i>0;i--)
	{
		ofp_flow_mod* ofm;
    	size_t size = sizeof *ofm + sizeof(ofp_action_output);
    	boost::shared_array<char> raw_of(new char[size]);
    	ofm = (ofp_flow_mod*) raw_of.get();
		ofp_action_output& action = *((ofp_action_output*)ofm->actions);
		ofm->header.version = OFP_VERSION;
		ofm->header.type = OFPT_FLOW_MOD;
	    ofm->header.length = htons(size);
		ofm->match.wildcards = htonl(0xfffffffe);
		VLOG_INFO(lg,"set_flow_entry | this is 1");	      	
		if(i == 2)        	
			ofm->match.in_port = htons(in_port);
		else if(i == 1)
			ofm->match.in_port = htons(out_port);
        else
            break;
		VLOG_INFO(lg,"set_flow_entry | this is 2");	
		ofm->cookie = htonl(0);
		ofm->command = htons(OFPFC_ADD);
		VLOG_INFO(lg,"set_flow_entry | this is 3");
		ofm->buffer_id = htonl(-1);
		ofm->idle_timeout = htons(0);
		ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
		ofm->priority = htons(OFP_DEFAULT_PRIORITY);
		ofm->flags = htons(ofd_flow_mod_flags());
		memset(&action, 0, sizeof(ofp_action_output));
		action.type = htons(OFPAT_OUTPUT);
		action.len = htons(sizeof(ofp_action_output));
		action.max_len = htons(1000);
		VLOG_INFO(lg,"set_flow_entry | this is 4");	     		
		action.port = htons(out_port);
		if(i == 2)        	
			action.port = htons(out_port);
		else if(i == 1)
			action.port = htons(in_port);
        else
            break;
		VLOG_INFO(lg,"set_flow_entry | this is 5");	
		send_openflow_command(dpid, &ofm->header, true);
		
	}
}

/*
 * FUNC: to create a arp reply to ask the whole switch and host 
 * 		after receive a arp request from a host or switch.s
 */
void Topology::sendARPReply(datapathid dpid, uint32_t port, ethernetaddr senderMAC, uint32_t senderIP, ethernetaddr targetMAC, uint32_t targetIP)
  {
	VLOG_INFO(lg,"sendARPReply | this is sendARPReply from %d to %d",senderIP,targetIP);
    ethernet ethPacket;
    arp arpPacket;

    ethPacket.daddr = targetMAC;

    ethPacket.saddr = senderMAC;
    ethPacket.type = ethernet::ARP;

    arpPacket.hrd = arp::ETHER;
    arpPacket.pro = ethernet::IP;
    arpPacket.hln = ethernet::PAYLOAD_MIN;  //6 for ethernet
    arpPacket.pln = sizeof(targetIP);       //4 for IPV4
    arpPacket.sha = senderMAC;
    arpPacket.sip = senderIP;
    arpPacket.tha = targetMAC;
    arpPacket.tip = targetIP;
    arpPacket.op  = arp::REPLY;

    int size = sizeof(ethernet) + sizeof(arp);
    uint8_t *data = new uint8_t[size];

    memcpy(data, &ethPacket, sizeof(ethPacket));
    memcpy(data + sizeof(ethPacket), &arpPacket, sizeof(arpPacket));
    Array_buffer buffer(data,size);  // data will be deleted automatically
	VLOG_INFO(lg,"sendARPReply | this is sendARPReply | send_openflow_packet from %d to %d,dpid is %s",senderIP,targetIP,dpid.string().c_str());
    send_openflow_packet(dpid, buffer, OFPP_ALL, OFPP_LOCAL, true);  //OFPP_LOCAL\u662f\u865a\u62df\u7684\uff0cport\u5219\u662fpacket-in\u4e8b\u4ef6\u53d1\u751f\u7684\u7aef\u53e3\u3002
 }


void Topology::sendARPRequest(datapathid dpid, uint32_t port, ethernetaddr senderMAC, uint32_t senderIP, ethernetaddr targetMAC, uint32_t targetIP)
{
	VLOG_INFO(lg,"sendARPRequest | this is sendARPRequest from %d to %d",senderIP,targetIP);
    ethernet ethPacket;
    arp arpPacket;

    ethPacket.daddr = targetMAC;

    ethPacket.saddr = senderMAC;
    ethPacket.type = ethernet::ARP;

    arpPacket.hrd = arp::ETHER;
    arpPacket.pro = ethernet::IP;
    arpPacket.hln = ethernet::PAYLOAD_MIN;  //6 for ethernet
    arpPacket.pln = sizeof(targetIP);       //4 for IPV4
    arpPacket.sha = senderMAC;
    arpPacket.sip = senderIP;
    arpPacket.tha = targetMAC;
    arpPacket.tip = targetIP;
    arpPacket.op  = arp::REQUEST;

    int size = sizeof(ethernet) + sizeof(arp);
    uint8_t *data = new uint8_t[size];

    memcpy(data, &ethPacket, sizeof(ethPacket));
    memcpy(data + sizeof(ethPacket), &arpPacket, sizeof(arpPacket));
    Array_buffer buffer(data,size);  // data will be deleted automatically
    
    int ret;
    ret = send_openflow_packet(dpid, buffer, OFPP_ALL, OFPP_LOCAL, true);  //OFPP_LOCAL\u662f\u865a\u62df\u7684\uff0cport\u5219\u662fpacket-in\u4e8b\u4ef6\u53d1\u751f\u7684\u7aef\u53e3\u3002port = OFPP_FLOOD
    if( ret == 0)
        VLOG_INFO(lg, "sendARPRequest | success");
}

/*
 *FUNC to find the by pass road for create a connection
 */
Disposition
Topology::set_bypass(ArpPair::iterator iter)
{
    VLOG_INFO(lg, "set bypass, size is %d", bypass_dpid.size());
    std::vector<datapathid>::iterator tmp_iter = bypass_dpid.begin();
    std::vector<datapathid>::iterator tmp_1_iter = bypass_dpid.begin();   
    std::vector<datapathid>::iterator head_iter = bypass_dpid.begin();
    std::vector<datapathid>::iterator tail_iter = bypass_dpid.begin() + bypass_dpid.size() - 1;
   
    /*--------------------test 1-------------------*/
    /*
    while(tmp_iter != bypass_dpid.end()){
        VLOG_INFO(lg, "PASS is %s ", tmp_iter->string().c_str());
        tmp_iter++;
    }
    */

    VLOG_INFO(lg, "THIS IS SET BYPASS");
    VLOG_INFO(lg, "******************************************");

    std::vector<set_flow_t> set_flow;
    set_flow_t tmp_flow_s;
    hash_map<datapathid, LinkPorts>::iterator find_next;    
    std::vector<datapathid>::iterator dpid_iter = bypass_dpid.begin();
    std::vector<datapathid>::iterator dpid_iter_tmp;
    uint16_t sizeof_bypass = bypass_dpid.size();
    SwMap::iterator set_flow_iter;
    set_flow_iter = store_swmap.find(*dpid_iter);
    hash_map<datapathid, LinkPorts>::iterator set_flow_child_iter;
    datapathid tmp_dpid;
    LinkPorts tmp_lp;
    uint16_t prev_port;

    while(1)
    {
        VLOG_INFO(lg, "sizeof_bypass is %d",sizeof_bypass);
        if( *dpid_iter == iter->dpidsrc){
            prev_port = iter->src_in_port;
            for(uint16_t i = 0; i < sizeof_bypass - 1; i++){
                VLOG_INFO(lg, "adding dpid is %s", (*dpid_iter).string().c_str());
                tmp_flow_s.dpid = *dpid_iter;
                set_flow_iter = store_swmap.find(*dpid_iter);
                dpid_iter_tmp = dpid_iter + 1;
                set_flow_child_iter = set_flow_iter->second.find(*dpid_iter_tmp);

                tmp_flow_s.dpid = *dpid_iter;
                
                tmp_flow_s.src_port = prev_port;
                tmp_flow_s.dst_port = set_flow_child_iter->second.src;
                prev_port = set_flow_child_iter->second.dst;
                set_flow.push_back(tmp_flow_s);
                dpid_iter++;
            }

            VLOG_INFO(lg, "adding out of dpid is %s", (*dpid_iter).string().c_str());            
            tmp_flow_s.dpid = *dpid_iter;
            tmp_flow_s.src_port = set_flow_child_iter->second.dst;
            tmp_flow_s.dst_port = iter->dst_in_port;
            set_flow.push_back(tmp_flow_s);
            break;
        }else if(*dpid_iter == iter->dpiddst){
            dpid_iter = bypass_dpid.begin() + bypass_dpid.size() - 1;
            prev_port = iter->src_in_port;
            for(uint16_t i = 0; i < sizeof_bypass - 1; i++){
                VLOG_INFO(lg, "adding dpid is %s", (*dpid_iter).string().c_str());
                tmp_flow_s.dpid = *dpid_iter;
                set_flow_iter = store_swmap.find(*dpid_iter);
                dpid_iter_tmp = dpid_iter - 1;
                set_flow_child_iter = set_flow_iter->second.find(*dpid_iter_tmp);

                tmp_flow_s.dpid = *dpid_iter;
                
                tmp_flow_s.src_port = prev_port;
                tmp_flow_s.dst_port = set_flow_child_iter->second.src;
                prev_port = set_flow_child_iter->second.dst;
                set_flow.push_back(tmp_flow_s);
                dpid_iter--;
            }

            VLOG_INFO(lg, "adding out of dpid is %s", (*dpid_iter).string().c_str());            
            tmp_flow_s.dpid = *dpid_iter;
            tmp_flow_s.src_port = set_flow_child_iter->second.dst;
            tmp_flow_s.dst_port = iter->dst_in_port;
            set_flow.push_back(tmp_flow_s);
            break;
        }else{
            return CONTINUE;
        }            
    }

    VLOG_INFO(lg, "size of set_flow is %d", set_flow.size());
    std::vector<set_flow_t>::iterator viter = set_flow.begin();
    while(viter != set_flow.end())
    {
        VLOG_INFO(lg, "dpid is %s, src port is %d, dst port is %d", 
                        viter->dpid.string().c_str(), viter->src_port, viter->dst_port);
        viter++;
    }    

    /*set flow entry and send them to the switch*/
    std::vector<set_flow_t>::iterator sft_iter = set_flow.begin();
    while(sft_iter != set_flow.end()){
        set_flow_entry(sft_iter->src_port, sft_iter->dst_port, sft_iter->dpid);
        sft_iter++;
    }
    
    return CONTINUE;
}


Disposition
Topology::road_find(ArpPair::iterator iter)
{
    datapathid src_dpid = iter->dpidsrc;
    datapathid dst_dpid = iter->dpiddst;  
    SwMap::iterator swmap_iter = store_swmap.find(src_dpid);
    int ret;

    if(swmap_iter == store_swmap.end())
        return STOP;
    
    std::vector<datapathid>::iterator tmp_head;
    std::vector<datapathid>::iterator tmp_tail;
    if(bypass_dpid.size() != 0){
        tmp_head = bypass_dpid.begin();
        tmp_tail = bypass_dpid.begin() + bypass_dpid.size() - 1;
        if( tmp_head != tmp_tail ){
            if(*tmp_head == src_dpid && *tmp_tail == dst_dpid)
                return CONTINUE;
            if(*tmp_head == dst_dpid && *tmp_tail == src_dpid)
                return CONTINUE;
        }
    }
    bypass_dpid.push_back(src_dpid);

REPLAY:
    VLOG_INFO(lg, "calculate the road");
    hash_map<datapathid, LinkPorts>::iterator dpid_bypass_iter 
                                = swmap_iter->second.begin();
    while(dpid_bypass_iter != swmap_iter->second.end())
    {
        if(dpid_bypass_iter->first == dst_dpid)
        {
            bypass_dpid.push_back(dst_dpid);
            ret = set_bypass(iter);
            if(ret == STOP)
                return STOP;
            goto END;
        }else if(dpid_bypass_iter->first == src_dpid){
            continue;
        }else{
            bypass_dpid.push_back(dpid_bypass_iter->first);
            break;
        }
        dpid_bypass_iter++;
    }

    if(dpid_bypass_iter != swmap_iter->second.end()){
        swmap_iter  = store_swmap.find(dpid_bypass_iter->first);
        goto REPLAY;
    }

    if(dpid_bypass_iter == swmap_iter->second.end())
        return STOP;
    /*while(1){
        hash_map<datapathid, LinkPorts>::iterator tmp_dst_iter = swmap_iter->second.find(iter->dpiddst);
        if(tmp_dst_iter == swmap_iter->second.end()){
            for(tmp_dst_iter = swmap_iter->second.begin())
                if( tmp_dst_iter->first != iter->dpidsrc ){
                    bypass_dpid.push_back(tmp_dst_iter->first);
                    continue;
                }
                add_bypass();
        }else{        
          set_flow_entry(tmp_dst_iter->second.src, iter->src_in_port, iter->dpidsrc);
          set_flow_entry(iter->dst_in_port, tmp_dst_iter->second.dst, iter->dpiddst);
          
        } 
        
    }*/

END:
    return CONTINUE;
}

Disposition
Topology::handle_packet_in(const Event& e)
{
 	struct in_addr src;
	struct in_addr dst;
  
	const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
	Flow flow(pi.in_port, *pi.get_buffer());

    ipaddr ipsrc(ntohl(flow.nw_src));
	src.s_addr = ipsrc.addr;
	char *p_src = inet_ntoa(src);

    ipaddr ipdst(ntohl(flow.nw_dst));
	dst.s_addr =ipdst.addr;
	char *p_dst = inet_ntoa(dst);

    ethernetaddr senderMAC(flow.dl_src.string().c_str());
    ethernetaddr targetMAC(flow.dl_dst.string().c_str());

    if (flow.dl_type == ethernet::ARP)
	{
		VLOG_INFO(lg,"packet_in | this is arp");
	   // uint32_t buffer_id = pi.buffer_id;//	

        Nonowning_buffer b(*pi.get_buffer());
     	const arp_eth_header* arp = NULL;
      	const eth_header* eth = b.try_pull<eth_header>();//get the eth_head from the front of 'b'
		
        if (b.size() >= ARP_ETH_HEADER_LEN) 
		{
       	    arp = reinterpret_cast<const arp_eth_header*>(b.try_pull(ARP_ETH_HEADER_LEN));
            //get the apr_eth_header from the front of 'b' which has been pulled the size of eth_header
     	}else {
      	    return CONTINUE;
    	}

        src.s_addr = ntohl(arp->ar_spa);
        dst.s_addr = ntohl(arp->ar_tpa);
        p_src = inet_ntoa(src);     
        p_dst = inet_ntoa(dst);

    	if (arp->ar_op == arp::REQUEST)
    	{
    	    VLOG_INFO(lg, "get arp_request");
    	    /*    struct ArpPair_s{
                        datapathid dpidsrc;
                        datapathid dpiddst;
                        ipaddr ipsrc;
                        ipaddr ipdst;
                   };
                    typedef std::vector<struct ArpPair_s> ArpPair;
    	    */
    	    std::vector<struct ArpPair_s>::iterator arp_iter = store_arppair.begin();
            struct ArpPair_s tmp_arp_iter;

            tmp_arp_iter.dpidsrc = pi.datapath_id;
            tmp_arp_iter.ipdst = ipdst;
            tmp_arp_iter.ipsrc = ipsrc;
            tmp_arp_iter.macsrc = senderMAC;
            tmp_arp_iter.macdst = targetMAC;
            tmp_arp_iter.src_in_port = pi.in_port;
            tmp_arp_iter.status = 0;

            VLOG_INFO(lg, "get arp_request");
            VLOG_INFO(lg, "packet_in dpid_src is %s",tmp_arp_iter.dpidsrc.string().c_str());
            VLOG_INFO(lg, "packet_in ipsrc is %s, ipdst is %s", tmp_arp_iter.ipsrc.string().c_str(), tmp_arp_iter.ipdst.string().c_str());
            VLOG_INFO(lg, "packet_in in_port is %d",tmp_arp_iter.src_in_port);
            VLOG_INFO(lg, "packet_in mac src is %02x:%02x:%02x:%02x:%02x:%02x",tmp_arp_iter.macsrc.octet[0],tmp_arp_iter.macsrc.octet[1]
                                                                ,tmp_arp_iter.macsrc.octet[2],tmp_arp_iter.macsrc.octet[3]
                                                                ,tmp_arp_iter.macsrc.octet[4],tmp_arp_iter.macsrc.octet[5]);
            VLOG_INFO(lg, "packet_in mac dst is %02x:%02x:%02x:%02x:%02x:%02x",tmp_arp_iter.macdst.octet[0],tmp_arp_iter.macdst.octet[1]
                                                                ,tmp_arp_iter.macdst.octet[2],tmp_arp_iter.macdst.octet[3]
                                                                ,tmp_arp_iter.macdst.octet[4],tmp_arp_iter.macdst.octet[5]);

            
            while(arp_iter != store_arppair.end()){
                if(tmp_arp_iter.dpidsrc == arp_iter->dpidsrc && 
                    tmp_arp_iter.ipdst == arp_iter->ipdst &&
                    tmp_arp_iter.ipsrc == arp_iter->ipsrc &&
                    tmp_arp_iter.macsrc == arp_iter->macsrc &&
                    tmp_arp_iter.macdst == arp_iter->macdst){
                    return CONTINUE;  
                }
                arp_iter++;
            }
            if(arp_iter == store_arppair.end())
               store_arppair.push_back(tmp_arp_iter);
            
    	    VLOG_INFO(lg,"packet_in | arp::REQUEST | this is arp request");
            for(SwMap::iterator tmp_swmap_iter = store_swmap.begin(); 
                tmp_swmap_iter != store_swmap.end(); tmp_swmap_iter++)//different dpid need a sendARPRequest
            {
                sendARPRequest(tmp_swmap_iter->first, OFPP_LOCAL, tmp_arp_iter.macsrc, tmp_arp_iter.ipsrc.addr, tmp_arp_iter.macdst, tmp_arp_iter.ipdst.addr);
            }
            return CONTINUE;
        }else if(arp->ar_op == arp::REPLY){
            /*HANDLE THE ARP REPLY
             *look up the host which send the request ,send a fake reply to it, and make a flow mod 
             * and build the load.
             */
            struct ArpPair_s tmp_arp_iter;
            tmp_arp_iter.dpiddst = pi.datapath_id;
            tmp_arp_iter.ipdst = ipsrc;
            tmp_arp_iter.ipsrc = ipdst;
            tmp_arp_iter.macsrc = targetMAC;
            tmp_arp_iter.macdst = senderMAC;         
            tmp_arp_iter.dst_in_port = pi.in_port;

            VLOG_INFO(lg, "get arp_reply");
            VLOG_INFO(lg, "packet_in dpid_dst is %s",tmp_arp_iter.dpiddst.string().c_str());
            VLOG_INFO(lg, "packet_in ipsrc is %s, ipdst is %s", tmp_arp_iter.ipsrc.string().c_str(), tmp_arp_iter.ipdst.string().c_str());
            VLOG_INFO(lg, "packet_in in_port is %d",tmp_arp_iter.dst_in_port);
            VLOG_INFO(lg, "packet_in mac src is %02x:%02x:%02x:%02x:%02x:%02x",tmp_arp_iter.macsrc.octet[0],tmp_arp_iter.macsrc.octet[1]
                                                                ,tmp_arp_iter.macsrc.octet[2],tmp_arp_iter.macsrc.octet[3]
                                                                ,tmp_arp_iter.macsrc.octet[4],tmp_arp_iter.macsrc.octet[5]);
            VLOG_INFO(lg, "packet_in mac dst is %02x:%02x:%02x:%02x:%02x:%02x",tmp_arp_iter.macdst.octet[0],tmp_arp_iter.macdst.octet[1]
                                                                ,tmp_arp_iter.macdst.octet[2],tmp_arp_iter.macdst.octet[3]
                                                                ,tmp_arp_iter.macdst.octet[4],tmp_arp_iter.macdst.octet[5]);
            
    	    std::vector<struct ArpPair_s>::iterator arp_iter = store_arppair.begin();
            while(arp_iter != store_arppair.end()){
                if( tmp_arp_iter.ipdst == arp_iter->ipdst &&
                    tmp_arp_iter.ipsrc == arp_iter->ipsrc &&
                    tmp_arp_iter.macsrc == arp_iter->macsrc){

                    arp_iter->dpiddst = tmp_arp_iter.dpiddst;
                    arp_iter->macdst = tmp_arp_iter.macdst;
                    arp_iter->dst_in_port = tmp_arp_iter.dst_in_port;
                    arp_iter->status = 1;
                    VLOG_INFO(lg, "get arp pair");
                    VLOG_INFO(lg, "packet_in dpid_src is %s --------- dpid_dst is %s", tmp_arp_iter.dpidsrc.string().c_str(), tmp_arp_iter.dpiddst.string().c_str());
                    VLOG_INFO(lg, "packet_in ipsrc is %s, ipdst is %s", tmp_arp_iter.ipsrc.string().c_str(), tmp_arp_iter.ipdst.string().c_str());
                    VLOG_INFO(lg, "packet_in src in_port is %d ----- dst in_port is %d", tmp_arp_iter.src_in_port, tmp_arp_iter.dst_in_port);
                    VLOG_INFO(lg, "packet_in mac src is %02x:%02x:%02x:%02x:%02x:%02x",tmp_arp_iter.macsrc.octet[0],tmp_arp_iter.macsrc.octet[1]
                                                                        ,tmp_arp_iter.macsrc.octet[2],tmp_arp_iter.macsrc.octet[3]
                                                                        ,tmp_arp_iter.macsrc.octet[4],tmp_arp_iter.macsrc.octet[5]);
                    VLOG_INFO(lg, "packet_in mac dst is %02x:%02x:%02x:%02x:%02x:%02x",tmp_arp_iter.macdst.octet[0],tmp_arp_iter.macdst.octet[1]
                                                                        ,tmp_arp_iter.macdst.octet[2],tmp_arp_iter.macdst.octet[3]
                                                                        ,tmp_arp_iter.macdst.octet[4],tmp_arp_iter.macdst.octet[5]);
                    
                    sendARPReply(arp_iter->dpidsrc, OFPP_LOCAL, tmp_arp_iter.macdst, tmp_arp_iter.ipsrc.addr, tmp_arp_iter.macsrc, tmp_arp_iter.ipdst.addr);
                    break;
                }// end of if
                arp_iter++;
            }//end of while
            if(arp_iter == store_arppair.end())
                return CONTINUE;
            road_find(arp_iter);
            return CONTINUE;
        }else{
             return CONTINUE;
        }//end of 
    }//end of arp
    return CONTINUE;
} 
/********************************************************************/


const Topology::DpInfo&
Topology::get_dpinfo(const datapathid& dp) const
{
    NetworkLinkMap::const_iterator nlm_iter = topology.find(dp);

    if (nlm_iter == topology.end()) {
        return empty_dp;
    }

    return nlm_iter->second;
}

const Topology::DatapathLinkMap&
Topology::get_outlinks(const datapathid& dpsrc) const
{
    NetworkLinkMap::const_iterator nlm_iter = topology.find(dpsrc);

    if (nlm_iter == topology.end()) {
        return empty_dp.outlinks;
    }

    return nlm_iter->second.outlinks;
}


const Topology::LinkSet&
Topology::get_outlinks(const datapathid& dpsrc, const datapathid& dpdst) const
{
    NetworkLinkMap::const_iterator nlm_iter = topology.find(dpsrc);

    if (nlm_iter == topology.end()) {
        return empty_link_set;
    }

    DatapathLinkMap::const_iterator dlm_iter = nlm_iter->second.outlinks.find(dpdst);
    if (dlm_iter == nlm_iter->second.outlinks.end()) {
        return empty_link_set;
    }

    return dlm_iter->second;
}


bool
Topology::is_internal(const datapathid& dp, uint16_t port) const
{
    NetworkLinkMap::const_iterator nlm_iter = topology.find(dp);

    if (nlm_iter == topology.end()) {
        return false;
    }

    PortMap::const_iterator pm_iter = nlm_iter->second.internal.find(port);
    return (pm_iter != nlm_iter->second.internal.end());
}

std::list<datapathid> 
Topology::get_datapaths()
{
    std::list<datapathid> returnme;
    Topology::NetworkLinkMap::iterator dpit;
    for(dpit = topology.begin(); dpit != topology.end(); dpit++) {
	returnme.push_back(datapathid(dpit->first));
    }
    return returnme;
}


Disposition
Topology::handle_datapath_join(const Event& e)
{
    const Datapath_join_event& dj = assert_cast<const Datapath_join_event&>(e);
    NetworkLinkMap::iterator nlm_iter = topology.find(dj.datapath_id);

    if (nlm_iter == topology.end()) {
        nlm_iter = topology.insert(std::make_pair(dj.datapath_id,
                                                  DpInfo())).first;
    }

    nlm_iter->second.active = true;
    nlm_iter->second.ports = dj.ports;
    return CONTINUE;
}

Disposition
Topology::handle_datapath_leave(const Event& e)
{
    const Datapath_leave_event& dl = assert_cast<const Datapath_leave_event&>(e);
    NetworkLinkMap::iterator nlm_iter = topology.find(dl.datapath_id);

    if (nlm_iter != topology.end()) {
        if (!(nlm_iter->second.internal.empty()
              && nlm_iter->second.outlinks.empty()))
        {
            nlm_iter->second.active = false;
            nlm_iter->second.ports.clear();
        } else {
            topology.erase(nlm_iter);
        }
    } else {
        VLOG_ERR(lg, "Received datapath_leave for non-existing dp %"PRIx64".",
                 dl.datapath_id.as_host());
    }
    return CONTINUE;
}

Disposition
Topology::handle_port_status(const Event& e)
{
    const Port_status_event& ps = assert_cast<const Port_status_event&>(e);

    if (ps.reason == OFPPR_DELETE) {
        delete_port(ps.datapath_id, ps.port);
    } else {
        add_port(ps.datapath_id, ps.port, ps.reason != OFPPR_ADD);
    }

    return CONTINUE;
}

void
Topology::add_port(const datapathid& dp, const Port& port, bool mod)
{
    NetworkLinkMap::iterator nlm_iter = topology.find(dp);
    if (nlm_iter == topology.end()) {
        VLOG_WARN(lg, "Add/mod port %"PRIu16" to unknown datapath %"PRIx64" - adding default entry.",
                  port.port_no, dp.as_host());
        nlm_iter = topology.insert(std::make_pair(dp,
                                                  DpInfo())).first;
        nlm_iter->second.active = false;
        nlm_iter->second.ports.push_back(port);
        return;
    }

    for (std::vector<Port>::iterator p_iter = nlm_iter->second.ports.begin();
         p_iter != nlm_iter->second.ports.end(); ++p_iter)
    {
        if (p_iter->port_no == port.port_no) {
            if (!mod) {
                VLOG_DBG(lg, "Add known port %"PRIu16" on datapath %"PRIx64" - modifying port.",
                         port.port_no, dp.as_host());
            }
            *p_iter = port;
            return;
        }
    }

    if (mod) {
        VLOG_DBG(lg, "Mod unknown port %"PRIu16" on datapath %"PRIx64" - adding port.",
                 port.port_no, dp.as_host());
    }
    nlm_iter->second.ports.push_back(port);
}

void
Topology::delete_port(const datapathid& dp, const Port& port)
{
    NetworkLinkMap::iterator nlm_iter = topology.find(dp);
    if (nlm_iter == topology.end()) {
        VLOG_ERR(lg, "Delete port from unknown datapath %"PRIx64".",
                 dp.as_host());
        return;
    }

    for (std::vector<Port>::iterator p_iter = nlm_iter->second.ports.begin();
         p_iter != nlm_iter->second.ports.end(); ++p_iter)
    {
        if (p_iter->port_no == port.port_no) {
            nlm_iter->second.ports.erase(p_iter);
            return;
        }
    }

    VLOG_ERR(lg, "Delete unknown port %"PRIu16" from datapath %"PRIx64".",
             port.port_no, dp.as_host());
}

Disposition
Topology::handle_link_event(const Event& e)
{
	lg.info("link event");
    const Link_event& le = assert_cast<const Link_event&>(e);
    if (le.action == Link_event::ADD) {
        std::cout<<le.sport<<le.dport<<std::endl;
        add_dpid(le);
        add_link(le);
    } else if (le.action == Link_event::REMOVE) {
        remove_link(le);
    } else {
        lg.err("unknown link action %u", le.action);
    }

    return CONTINUE;
}

void Topology::add_dpid(const Link_event& le)
{
   // std::cout<<"src dpis is"<<le.dpsrc.as_host()<<std::endl;
   // std::cout<<"dst dpis is"<<le.dpdst.as_host()<<std::endl;
    /**
     *    typedef hash_map<datapathid, std::vector<datapathid> > SwMap;
     */
   SwMap::iterator swmap_iter_src = store_swmap.find(le.dpsrc);
   SwMap::iterator swmap_iter_dst = store_swmap.find(le.dpdst);     
   hash_map<datapathid, LinkPorts> new_src_link;  
   hash_map<datapathid, LinkPorts> new_dst_link;
   LinkPorts tmp_ports_src, tmp_ports_dst;
   tmp_ports_src.dst = le.dport;
   tmp_ports_src.src = le.sport;
   tmp_ports_dst.dst = le.sport;
   tmp_ports_dst.src = le.dport;
   
   if(swmap_iter_src == store_swmap.end()){
        new_src_link.insert(std::make_pair(le.dpdst, tmp_ports_src));
        swmap_iter_src = store_swmap.insert(std::make_pair(le.dpsrc, new_src_link)).first;
   }else{
        hash_map<datapathid, LinkPorts>::iterator tmp_iter;
        tmp_iter = swmap_iter_src->second.find(le.dpdst);
        if( tmp_iter == swmap_iter_src->second.end())
            swmap_iter_src->second.insert(std::make_pair(le.dpdst, tmp_ports_src));
   }

   if(swmap_iter_dst == store_swmap.end()){ 
        new_dst_link.insert(std::make_pair(le.dpsrc, tmp_ports_dst));
        swmap_iter_dst = store_swmap.insert(std::make_pair(le.dpdst, new_dst_link)).first;
   }else{
        hash_map<datapathid, LinkPorts>::iterator tmp_iter;
        tmp_iter = swmap_iter_dst->second.find(le.dpsrc);
        if( tmp_iter == swmap_iter_dst->second.end())
            swmap_iter_dst->second.insert(std::make_pair(le.dpsrc, tmp_ports_dst));
   }
   
   /*uint test 1*/
   /*
   std::cout<<"--------begin of test 1-----------"<<std::endl;
   std::vector<struct SwLinks>::iterator iter = store_swlink.begin();
   for(;iter != store_swlink.end();iter++){
        std::cout<<"src dpis is"<<iter->dpidsrc<<std::endl;
        std::cout<<"dst dpis is"<<iter->dpiddst<<std::endl;
        std::cout<<"src port is"<<iter->src<<std::endl;
        std::cout<<"src port is"<<iter->dst<<std::endl;
   }
   std::cout<<"--------end of test 1-----------"<<std::endl;
   */

   /*uint test 2*/
   
   std::cout<<"--------begin of test 1-----------"<<std::endl;  
   SwMap::iterator swmap_iter = store_swmap.begin();
   while(swmap_iter != store_swmap.end())
   {
        hash_map<datapathid, LinkPorts>::iterator viter = swmap_iter->second.begin();
        std::cout<<"dpid : "<<swmap_iter->first.as_host()<<std::endl;
        while(viter != swmap_iter->second.end()){
            std::cout<<"child-dpid : "<<viter->first.as_host()<<"\tsrc_port is"<<viter->second.src\
                            <<"\tdst_port is"<<viter->second.dst<<std::endl;
            viter++;
        }
        swmap_iter++;
   }
   std::cout<<"--------end of test 1-----------"<<std::endl;
   
}

void
Topology::add_link(const Link_event& le)
{
	lg.info("add_link");
    NetworkLinkMap::iterator nlm_iter = topology.find(le.dpsrc);
    DatapathLinkMap::iterator dlm_iter;
    if (nlm_iter == topology.end()) {
        VLOG_INFO(lg, "Add link to unknown datapath %"PRIx64" - adding default entry.",
                  le.dpsrc.as_host());
        nlm_iter = topology.insert(std::make_pair(le.dpsrc,
                                                  DpInfo())).first;
        nlm_iter->second.active = false;
        dlm_iter = nlm_iter->second.outlinks.insert(std::make_pair(le.dpdst,
                                                                   LinkSet())).first;
    } else {
        dlm_iter = nlm_iter->second.outlinks.find(le.dpdst);
        if (dlm_iter == nlm_iter->second.outlinks.end()) {
            dlm_iter = nlm_iter->second.outlinks.insert(std::make_pair(le.dpdst,
                                                                       LinkSet())).first;
        }
    }

    LinkPorts lp = {le.sport, le.dport };
    dlm_iter->second.push_back(lp);
    add_internal(le.dpdst, le.dport);
}


void
Topology::remove_link(const Link_event& le)
{
    NetworkLinkMap::iterator nlm_iter = topology.find(le.dpsrc);
    if (nlm_iter == topology.end()) {
        lg.err("Remove link event for non-existing link %"PRIx64":%hu --> %"PRIx64":%hu (src dp)",
               le.dpsrc.as_host(), le.sport, le.dpdst.as_host(), le.dport);
        return;
    }

    DatapathLinkMap::iterator dlm_iter = nlm_iter->second.outlinks.find(le.dpdst);
    if (dlm_iter == nlm_iter->second.outlinks.end()) {
        lg.err("Remove link event for non-existing link %"PRIx64":%hu --> %"PRIx64":%hu (dst dp)",
               le.dpsrc.as_host(), le.sport, le.dpdst.as_host(), le.dport);
        return;
    }

    for (LinkSet::iterator ls_iter = dlm_iter->second.begin();
         ls_iter != dlm_iter->second.end(); ++ls_iter)
    {
        if (ls_iter->src == le.sport && ls_iter->dst == le.dport) {
            dlm_iter->second.erase(ls_iter);
            remove_internal(le.dpdst, le.dport);
            if (dlm_iter->second.empty()) {
                nlm_iter->second.outlinks.erase(dlm_iter);
                if (!nlm_iter->second.active && nlm_iter->second.ports.empty()
                    && nlm_iter->second.internal.empty()
                    && nlm_iter->second.outlinks.empty())
                {
                    topology.erase(nlm_iter);
                }
            }
            return;
        }
    }

    lg.err("Remove link event for non-existing link %"PRIx64":%hu --> %"PRIx64":%hu",
           le.dpsrc.as_host(), le.sport, le.dpdst.as_host(), le.dport);
}


void
Topology::add_internal(const datapathid& dp, uint16_t port)
{
    NetworkLinkMap::iterator nlm_iter = topology.find(dp);
    if (nlm_iter == topology.end()) {
        VLOG_WARN(lg, "Add internal to unknown datapath %"PRIx64" - adding default entry.",
                  dp.as_host());
        DpInfo& di = topology[dp] = DpInfo();
        di.active = false;
        di.internal.insert(std::make_pair(port, std::make_pair(port, 1)));
        return;
    }

    PortMap::iterator pm_iter = nlm_iter->second.internal.find(port);
    if (pm_iter == nlm_iter->second.internal.end()) {
        nlm_iter->second.internal.insert(
            std::make_pair(port, std::make_pair(port, 1)));
    } else {
        ++(pm_iter->second.second);
    }
}


void
Topology::remove_internal(const datapathid& dp, uint16_t port)
{
    NetworkLinkMap::iterator nlm_iter = topology.find(dp);
    if (nlm_iter == topology.end()) {
        lg.err("Remove internal for non-existing dp %"PRIx64":%hu",
               dp.as_host(), port);
        return;
    }

    PortMap::iterator pm_iter = nlm_iter->second.internal.find(port);
    if (pm_iter == nlm_iter->second.internal.end()) {
        lg.err("Remove internal for non-existing ap %"PRIx64":%hu.",
               dp.as_host(), port);
    } else {
        if (--(pm_iter->second.second) == 0) {
            nlm_iter->second.internal.erase(pm_iter);
            if (!nlm_iter->second.active && nlm_iter->second.ports.empty()
                && nlm_iter->second.internal.empty()
                && nlm_iter->second.outlinks.empty())
            {
                topology.erase(nlm_iter);
            }
        }
    }
}

}
}

REGISTER_COMPONENT(container::Simple_component_factory<Topology>, Topology);
