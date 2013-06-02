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
#ifndef TOPOLOGY_HH
#define TOPOLOGY_HH 1

#include <list>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <string>
#include <memory.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <vector>

#include "openflow/openflow.h"
#include "openflow-pack.hh"
#include "flow.hh"
#include "fnv_hash.hh"
#include "packet-in.hh"

#include "component.hh"
#include "hash_map.hh"
#include "discovery/link-event.hh"
#include "netinet++/datapathid.hh"
#include "port.hh"
#include "netinet++/arp.hh"//for arp
#include "packets.h"

namespace vigil {
namespace applications {

/*modify by wangq 20130531 to store the details about link*/
/*struct sw_link_s{
    uint64_t dpidsrc;
    uint64_t dpiddst;
    uint16_t src;
    uint16_t dst;
};
typedef struct sw_link_s sw_link_t;
*/
/*end of modify*/

/** \ingroup noxcomponents
 *
 * \brief The current network topology  
 */
class Topology
    : public container::Component {

public:
    /** \brief Structure to hold source and destination port
     */
    struct LinkPorts {
        uint16_t src;
        uint16_t dst;
    };
    
    /*mod by wangq 20130531*/
    typedef hash_map<datapathid, hash_map<datapathid, LinkPorts> > SwMap;

    struct ArpPair_s{
        datapathid dpidsrc;
        datapathid dpiddst;
        ipaddr ipsrc;
        ipaddr ipdst;
        ethernetaddr macsrc;
        ethernetaddr macdst;
        uint16_t src_in_port;
        uint16_t dst_in_port;
        uint16_t status;
    };
    typedef std::vector<struct ArpPair_s> ArpPair;

    struct set_flow_s{
        datapathid dpid;
        uint16_t src_port;
        uint16_t dst_port;
    };
    typedef struct set_flow_s set_flow_t;  
    /*end of mod*/

     
    typedef std::vector<Port> PortVector;
    typedef hash_map<uint16_t, std::pair<uint16_t, uint32_t> > PortMap;
    typedef std::list<LinkPorts> LinkSet;
    typedef hash_map<datapathid, LinkSet> DatapathLinkMap;

    /** \brief Structure to hold information about datapath
     */
    struct DpInfo {
        /** \brief List of ports for datapath
	 */
        PortVector ports;
        /** \brief Map of internal ports (indexed by port)
         */
        PortMap internal;
        /** \brief Map of outgoing links 
	 * (indexed by datapath id of switch on the other end)
	 */
        DatapathLinkMap outlinks;
        /** \brief Indicate if datapath is active
	 */
        bool active;
    };

    /** \brief Constructor
     */
    Topology(const container::Context*, const json_object*);

    /** \brief Get instance of component
     */
    static void getInstance(const container::Context*, Topology*&);

    /** \brief Configure components
     */
    void configure(const container::Configuration*);

    /** \brief Install components
     */
    void install();

    /** \brief Get information about datapath
     */
    const DpInfo& get_dpinfo(const datapathid& dp) const;
    /** \brief Get outgoing links of datapath
     */
    const DatapathLinkMap& get_outlinks(const datapathid& dpsrc) const;
    /** \brief Get links between two datapaths
     */
    const LinkSet& get_outlinks(const datapathid& dpsrc, const datapathid& dpdst) const;
    /** \brief Check if link is internal (i.e., between switches)
     */
    bool is_internal(const datapathid& dp, uint16_t port) const;
    /** \brief Get a list of datapaths in the network
     */
    std::list<datapathid> get_datapaths();

private:
    /**************************************************/
    /** \brief Map of information index by datapath id
     */
    typedef hash_map<datapathid, DpInfo> NetworkLinkMap;
    NetworkLinkMap topology;
    DpInfo empty_dp;
    LinkSet empty_link_set;
    /*mod by wangq 20130531*/
    SwMap store_swmap;
    ArpPair store_arppair;
    std::vector<datapathid> bypass_dpid;  
    /*end of mod*/
    
    //Topology() { }
    /*mod by wangq 20130531*/
    /* add dpid to LinkPorts
     */
    void add_dpid(const Link_event&);

    void set_flow_entry(const uint32_t , const uint32_t , const datapathid &);

    /* handle packet in
     */
    Disposition handle_packet_in(const Event&); 

    void sendARPReply(datapathid , uint32_t , ethernetaddr , uint32_t \
        , ethernetaddr , uint32_t );    

    void sendARPRequest(datapathid , uint32_t , ethernetaddr , uint32_t \
        , ethernetaddr , uint32_t );

    Disposition road_find(ArpPair::iterator);

    Disposition set_bypass(ArpPair::iterator);

    /**************************************/

    
    /** \brief Handle datapath join
     */
    Disposition handle_datapath_join(const Event&);
    /** \brief Handle datapath leave
     */
    Disposition handle_datapath_leave(const Event&);
    /** \brief Handle port status changes
     */
    Disposition handle_port_status(const Event&);
    /** \brief Handle link changes
     */
    Disposition handle_link_event(const Event&);

    /** \brief Add new port
     */
    void add_port(const datapathid&, const Port&, bool);
    /** \brief Delete port
     */
    void delete_port(const datapathid&, const Port&);

    /** \brief Add new link
     */
    void add_link(const Link_event&);
    /** \brief Delete link
     */
    void remove_link(const Link_event&);

    /** \brief Add new internal port
     */
    void add_internal(const datapathid&, uint16_t);
    /** \brief Remove internal port
     */
    void remove_internal(const datapathid&, uint16_t);
};

} // namespace applications
} // namespace vigil

#endif
