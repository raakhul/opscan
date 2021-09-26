use cidr::Ipv4Inet;
use std::net::{IpAddr, Ipv4Addr};
use pnet::datalink::{self};


#[derive(Debug)]
pub struct SrcSelector {
    pub source_ip: Ipv4Addr
}


impl SrcSelector {

    pub fn srcselect (target_ip: Ipv4Addr) -> (Ipv4Addr,bool) {

        // To select source ip with respect to target ip (within same network range) with corresponding interface
        let available_interfaces = datalink::interfaces();

        let mut src_ip_iter = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let source_ip = Ipv4Addr::new(127, 0, 0, 1);
        
        let mut srcip_prefix: u8 = 0;

        let network_availability: bool = false;

        for iface in available_interfaces {

            //println!("Interface Mac: {:?}",i.mac.unwrap());

            let ip_ver = iface.ips.len();

            if ip_ver > 0
            {
                if ip_ver == 1 {
                    if iface.ips[0].is_ipv4() {
                        src_ip_iter=iface.ips[0].ip();
                        srcip_prefix=iface.ips[0].prefix();
                    }
                }
                if ip_ver == 2 {
                    if iface.ips[0].is_ipv4() {
                        src_ip_iter=iface.ips[0].ip();
                        srcip_prefix=iface.ips[0].prefix();
                    }
                    if iface.ips[1].is_ipv4() {
                        src_ip_iter=iface.ips[1].ip();
                        srcip_prefix=iface.ips[1].prefix();
                    }

                }


                let source_ip = match src_ip_iter {
                    IpAddr::V4(ip4) => ip4,
                    IpAddr::V6(_ip6) => panic!("IPv6 Not Supported"),
                };

                let newsrc_ip=Ipv4Inet::new(source_ip ,srcip_prefix).unwrap();

                let network_availability = Ipv4Inet::contains(&newsrc_ip,&target_ip);

                if network_availability {

                    return (source_ip ,network_availability);
                }
            }
        }

        return (source_ip ,network_availability);
    }

}