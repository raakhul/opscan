use crate::util;
use std::{ net, thread, time };
use pnet::packet::{ tcp, ip };
use pnet::transport::{self, TransportProtocol};
use util::ports::MOST_COMMON_PORTS; 

const TCP_SIZE: usize = 20;
//const MAXIMUM_PORT_NUM: u16 = 1023;

#[derive(Debug)]
pub struct TcpScanner {
    pub source_ipaddr: net::Ipv4Addr,
    pub target_ipaddr: net::Ipv4Addr,
    pub port: u16,
    pub scan_type: ScanType,
}

#[derive(Copy, Clone, Debug)]
pub enum ScanType {
    SynScan = tcp::TcpFlags::SYN as isize,
    FinScan = tcp::TcpFlags::FIN as isize,
    XmasScan = tcp::TcpFlags::FIN as isize | tcp::TcpFlags::URG as isize | tcp::TcpFlags::PSH as isize,
    NullScan = 0
}


impl TcpScanner {

    pub fn initiate_tcpscan (tcppacket: TcpScanner)   {



        let (mut ts, mut tr) = transport::transport_channel(1024, transport::TransportChannelType::Layer4(TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Tcp))).unwrap();

        rayon::join(|| TcpScanner::send_packet(&mut ts, &tcppacket),
                    || TcpScanner::receive_packets(&mut tr, &tcppacket)
        );

    
    
    }

    fn build_packet(tcppacket: &TcpScanner) -> [u8; TCP_SIZE]{

        let mut tcp_buffer = [0u8; TCP_SIZE];
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
        tcp_header.set_source(tcppacket.port);
        tcp_header.set_data_offset(5);
        tcp_header.set_flags(tcppacket.scan_type as u16);
        let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &tcppacket.source_ipaddr, &tcppacket.target_ipaddr);
        tcp_header.set_checksum(checksum);
    
        return tcp_buffer;
    }

    fn send_packet(ts: &mut transport::TransportSender, tcppacket: &TcpScanner) {
        let mut packet = TcpScanner::build_packet(tcppacket);
        for i in MOST_COMMON_PORTS {
            let mut tcp_header = tcp::MutableTcpPacket::new(&mut packet).unwrap();
            TcpScanner::reregister_destination_port(*i, &mut tcp_header, tcppacket);
            thread::sleep(time::Duration::from_millis(5));
            ts.send_to(tcp_header, net::IpAddr::V4(tcppacket.target_ipaddr)).expect("failed to send");
        }
    }
    


    fn reregister_destination_port(target: u16, tcp_header: &mut tcp::MutableTcpPacket, tcppacket: &TcpScanner) {
        tcp_header.set_destination(target);
        let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &tcppacket.source_ipaddr, &tcppacket.target_ipaddr);
        tcp_header.set_checksum(checksum);
    }


    

    fn receive_packets(tr: &mut transport::TransportReceiver, tcppacket: &TcpScanner) {
        let mut reply_ports = Vec::new();
        let mut packet_iter = transport::tcp_packet_iter(tr);
        loop {

            let tcp_packet = match packet_iter.next() {
                Ok((tcp_packet, _)) => {
                    if tcp_packet.get_destination() != tcppacket.port {
                        continue;
                    }
                    tcp_packet
                }
                Err(_) => continue
            };
            
            let target_port = tcp_packet.get_source();
            match tcppacket.scan_type {
                ScanType::SynScan => {
                    if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                        println!("port {} is open", target_port);
                    }
                },

                ScanType::FinScan | ScanType::XmasScan | ScanType::NullScan => {
                    reply_ports.push(target_port);
                },
            }
            
            //println!("Target Port {}",target_port);
            if target_port != MOST_COMMON_PORTS[1000] {
                continue;
            }
            match tcppacket.scan_type {
                ScanType::FinScan | ScanType::XmasScan | ScanType::NullScan => {
                    for i in MOST_COMMON_PORTS {
                        match reply_ports.iter().find(|&&x| x == *i) {
                            None => {
                                println!("port {} is open", i);
                            },
                            _ => {}
                        }
                    }
                },
                _ => {}
            }
            return;
        }
    }
}