use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{
    ethernet::EthernetPacket,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    Packet
};
use std::env;
use etherparse::{TcpHeader};

fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <interface> <port>", args[0]);
        return;
    }

    //args
    let interface_name = &args[1];
    let target_port: u16 = args[2].parse().expect("Port incorrect");

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .expect("Interface not found");
    
    println!("Listen interface: {}, port: {}", interface.name, target_port);

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("This not eth channel"),
        Err(e) => panic!("Error open channel {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    let flags = tcp.get_flags();
                                    // Checking fucking syn
                                    if flags & 0x02 != 0 && flags & 0x10 == 0 {
                                        let dst_port = tcp.get_destination();
                                        if dst_port != target_port {
                                            continue; // ))
                                        }                                                                                         

                                        println!();
                                        println!("SYN packet:");
                                        println!("  > From: {}:{}", ipv4.get_source(), tcp.get_source());
                                        println!("  > To:   {}:{}", ipv4.get_destination(), tcp.get_destination());
                                        println!("  > Flags: {:#04x}", flags);
                                        if let Ok((tcp_header, _)) = TcpHeader::from_slice(ipv4.payload()) {
                                            let fingerprint = ja4t_fingerprint(&ipv4, &tcp_header, flags);
                                            println!("JA4T fingerprint: {}", fingerprint);
                                        }   
                                        println!();
                                        
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading packet: {}", e);
            }
        }
    }
}

fn ja4t_fingerprint(ipv4: &Ipv4Packet, tcp_header: &TcpHeader, tcp_flags: u8) -> String {
    let ttl = ipv4.get_ttl();
    let df = (ipv4.get_flags() & 0x2) >> 1;
    let window_size = tcp_header.window_size;
    let options = tcp_header.options();

    let mut mss: Option<u16> = None;
    let mut ws: Option<u8> = None;
    let mut opt_seq: Vec<String> = vec![];

    let mut i = 0;
    while i < options.len() {
        let kind = options[i];

        match kind {
            0 => {
                opt_seq.push("E".into());
                break;
            }
            1 => {
                opt_seq.push("N".into());
                i += 1;
            }
            2 => {
                if i + 3 < options.len() && options[i + 1] == 4 {
                    mss = Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
                    opt_seq.push("MSS".into());
                } else {
                    opt_seq.push("?".into());
                }
                i += 4;
            }
            3 => {
                if i + 2 < options.len() && options[i + 1] == 3 {
                    ws = Some(options[i + 2]);
                    opt_seq.push("WS".into());
                } else {
                    opt_seq.push("?".into());
                }
                i += 3;
            }
            4 => {
                opt_seq.push("SACK".into());
                i += 2;
            }
            8 => {
                opt_seq.push("TS".into());
                i += 10;
            }
            _ => {
                opt_seq.push(format!("OPT{:02X}", kind));
                if i + 1 < options.len() {
                    let len = options[i + 1] as usize;
                    if len >= 2 {
                        i += len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    let opt_str = format!(
        "{};{};SEQ={}",
        mss.map_or("MSS=?".into(), |v| format!("MSS={}", v)),
        ws.map_or("WS=?".into(), |v| format!("WS={}", v)),
        opt_seq.join(",")
    );

    format!("TTL={}|DF={}|{}|WIN={}|FLAGS={:#04x}", ttl, df, opt_str, window_size, tcp_flags)
}
