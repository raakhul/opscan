
use structopt::StructOpt;

use std::thread;
use std::net::{Ipv4Addr,TcpStream, ToSocketAddrs};


use std::time::Duration;
use pnet::datalink::{self, NetworkInterface,MacAddr};
use pnet::packet::arp::{ArpOperations, ArpOperation};

mod discovery;
mod scanner;
mod util;

use discovery::arpdiscovery::ArpDiscovery;
use scanner::tcpscanner::{TcpScanner,ScanType};
use util::srcselector::SrcSelector;


#[derive(Debug, StructOpt)]
#[structopt(name = "opscan")]
struct CliArgs {

    #[structopt(short = "H", long = "host", help = "Host Discovery Types", global = true, default_value = "")]
    host_discovery: String,
    
    #[structopt(short = "S", long = "scan", help = "Port Scanning Types", global = true, default_value = "")]
    scan_type: String,

    #[structopt(short = "P", long = "ports", help = "Port Numbers (1,2..65,535)", global = true, default_value = "")]
    ports: u16,

    #[structopt(short = "I", long = "interface", help = "Network Interface", global = true, default_value = "")]
    interface: String,

    //#[structopt(short = "TM", long = "target_mac", help = "Target Mac Address", global = true, default_value = "")]
    //target_mac: MacAddr,

    #[structopt(help = "Target IPv4 Address")]
    target_ip: Ipv4Addr, //dont change the type

}



    
/*
pub struct CustomTcpPacket {
    source: u16,
    destination: u16,
    sequence: u32,
    acknowledgement: u32,
    data_offset: u8,
    reserved: u8,
    flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
    options: Vec<TcpOption>,
    payload: Vec<u8>,
}*/


fn main () {

    let args = CliArgs::from_args();
 
    //let target=args.target_ip.trim().to_string();
    //println!("{}",args.target_ip);

    //  let my_local_ip = local_ip().unwrap();

    //    println!("This is my local IP address: {:?}", my_local_ip);



    //allow host discovery and tcp stealth scan 

    if args.host_discovery == "" && args.scan_type == "" { 
        println!("Host Discovery and Port Scanning");
    }
    else {
        if args.host_discovery != "" {

            println!("Performing Host Discovery");

            if args.host_discovery == "arp" {

                let mut packet_count: i32 = 0;

                let user_interface = args.interface.to_string();

                loop {

                    let mut source_mac =  MacAddr::new(00,00,00,00,00,00);
                    let source_ip = Ipv4Addr::new(127, 0, 0, 1);

                    let interfaces = datalink::interfaces();
    
                    let interfaces_name_match = |iface: &NetworkInterface| iface.name == user_interface;
                
                    for i in &interfaces 
                    {
                        if  i.name == user_interface {
                            source_mac = i.mac.unwrap();
                            //source_ip = i.ips.Ipv4Network.ip();
                        }
                    }
    
                    //println!("picked interface {:?}",interface);
                    let arp_operation_c: ArpOperation = ArpOperations::Request;
                    let interface = interfaces.into_iter().filter(interfaces_name_match).next().unwrap();

                    ArpDiscovery::send_arp_packet(interface, source_ip, source_mac, args.target_ip, source_mac, arp_operation_c);
            
                    packet_count += 1;
                    let arp_operation = match arp_operation_c {
                        ArpOperations::Request => "Request",
                        ArpOperations::Reply => "Reply",
                        ArpOperation(_) => panic!("Unknown operation")
                    };
                    println!("Sent {} ARP {} packets.", packet_count, arp_operation);
                    thread::sleep(Duration::new(1, 0));
                }
            }


        }
        if args.scan_type != "" {

            if args.scan_type == "syn" {
                println!("TCP Synchornize Scan");
            }
            else if args.scan_type == "fin" {
                println!("TCP Fin Scan");
            }
            else if args.scan_type == "xmas" {
                println!("TCP Xmas Scan");
            }
            else if args.scan_type == "null" {

                println!("TCP NULL Scan");

                /*
                //if args.ports != "" {


                    //let _ip_with_port = target+":"+&args.ports;
                    
                    
                    //scan_port_addr(&ip_with_port);
                    //println!("{} is {}",ip_with_port, );
                    //let mut test_vector: Vec<u8> = Vec::new();
                
                    
                    let mut buf = [0; 20];


                    println!("{:?}",&buf);

                    let mut custom_tcppacket = MutableTcpPacket::new(& mut buf).unwrap();
                    println!("{:?}",custom_tcppacket);
                    //let socket = udp::UdpSocket::bind("127.0.0.1:0").unwrap();
                    custom_tcppacket.set_source(1232);
                    custom_tcppacket.set_destination(80);
                    custom_tcppacket.set_sequence(0);
                    custom_tcppacket.set_acknowledgement(0);
                    custom_tcppacket.set_flags(TcpFlags::SYN);
                    custom_tcppacket.set_window(1024);
                    //custom_tcppacket.set_data_offset(8);
                    //let ts = TcpOption::timestamp(743951781, 44056978);
                    //custom_tcppacket.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);
            
                    //let checksum = ipv4_checksum(&custom_tcppacket.to_immutable(), &ipv4_source, &ipv4_destination);
                    //custom_tcppacket.set_checksum(checksum);
                    println!("{:?}",custom_tcppacket);
                   


                    

                //}
               */
              
                /*
                else {
                    println!("Common Ports are Scanned");

                    for portindex in ports::MOST_COMMON_PORTS_1002 {

                        //concatenate two &str
                        //let ip_with_commonports = format!("{}:{}", &target, &portindex.to_string());
                    //
                        //scan_port_addr(ip_with_commonports);
                    }
                }
                */
            }
            else {
                println!("Invalid Scanning Type");
                return;
            }


            let mut tcppacket: TcpScanner =  {
                        
                TcpScanner {
                    source_ipaddr: "127.0.0.1".parse().unwrap(),
                    target_ipaddr: "0.0.0.0".parse().unwrap(),
                    port: 0,
                    scan_type: ScanType::SynScan, 
                }
            };

            let src_result = SrcSelector::srcselect(args.target_ip);

            if src_result.1 {
                tcppacket.source_ipaddr=src_result.0;
            }
            else
            {
                println!("Target IP not within the available network range");
                return;
            }

            tcppacket.target_ipaddr=args.target_ip;
            tcppacket.port=args.ports;

            tcppacket.scan_type = match args.scan_type.as_str() {
                "syn" => ScanType::SynScan,
                "fin" => ScanType::FinScan,
                "xmas" => ScanType::XmasScan,
                "null" => ScanType::NullScan,
                _    => panic!("Undefined scan method")
            };

            

            TcpScanner::initiate_tcpscan(tcppacket);
        }
    }
}

pub fn scan_port_addr<A: ToSocketAddrs>(addr: A) {
    match TcpStream::connect(addr) {
        Ok(k) => println!("{:?}",k),
        Err(e) => println!("{}",e),
    }
}