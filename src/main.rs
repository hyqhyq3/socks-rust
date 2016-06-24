#![feature(ipv6_to_octets)]
use std::net::{TcpStream, TcpListener};
use std::thread;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, IpAddr};
use std::io::{Read, Write, Result};
use std::sync::{Arc, Mutex};

fn main() {
    let server = TcpListener::bind("0.0.0.0:1080").unwrap();

    struct Session {
        inbound: Arc<TcpStream>,
    }

    #[derive(Debug)]
    enum Cmd {
        Unknown = 0,
        Connect = 1,
        Bind = 2,
        UdpAssociate = 3,
    }

    #[derive(Debug)]
    enum Addr {
        Unknown,
        IPv4(Ipv4Addr),
        Domain(String),
        IPv6(Ipv6Addr),
    }

    #[derive(Debug)]
    struct SocksRequest {
        cmd: Cmd,
        addr: Addr,
        port: u32,
    }

    impl SocksRequest {
        fn new() -> SocksRequest {
            SocksRequest {
                cmd: Cmd::Unknown,
                addr: Addr::Unknown,
                port: 0,
            }
        }
    }

    fn pipe(mut r: Arc<TcpStream>, mut w: Arc<TcpStream>) {
        let mut r = Arc::get_mut(&mut r).unwrap();
        let mut w = Arc::get_mut(&mut w).unwrap();
        let mut buf = vec![0;1024];
        loop {
            let size = match r.read(&mut buf) {
                Ok(size) => size,
                _ => return,
            };
            println!("read {}", size);
            let wsize = match w.write(&buf[..size]) {
                Ok(wsize) if wsize == size => wsize,
                _ => return,
            };
            w.flush();
            println!("write {}", size);
        }
    }

    impl Session {
        fn new(s: TcpStream) -> Session {
            Session { inbound: Arc::new(s) }
        }

        fn start(&mut self) {
            if !self.handshake() {
                return;
            }
            println!("handshake ok");
            match self.read_request() {
                Some(req) => {
                    println!("read req {:?}", req);
                    let outbound = self.dial(req.addr, req.port);
                    match outbound {
                        Ok(outbound) => {
                            self.write_resp(0, outbound.local_addr().ok());
                            let outbound = Arc::new(outbound);
                            let inbound2 = self.inbound.clone();
                            let outbound2 = outbound.clone();
                            thread::spawn(move || pipe(inbound2, outbound2));
                            pipe(outbound, self.inbound.clone())
                        }
                        Err(_) => {
                            let _ = Arc::get_mut(&mut self.inbound)
                                .unwrap()
                                .write(&[0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00]);
                        }
                    }
                }
                None => (),
            }
        }

        fn dial(&self, a: Addr, p: u32) -> Result<TcpStream> {
            match a {
                Addr::IPv4(e) => TcpStream::connect(SocketAddr::new(IpAddr::V4(e), p as u16)),
                Addr::IPv6(e) => TcpStream::connect(SocketAddr::new(IpAddr::V6(e), p as u16)),
                Addr::Domain(d) => TcpStream::connect(&*format!("{}:{}", d, p)),
                _ => {
                    Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused,
                                            "cannot connect"))
                }
            }
        }

        fn handshake(&mut self) -> bool {
            let mut buf = vec![0;257];
            let inbound = Arc::get_mut(&mut self.inbound).unwrap();
            match inbound.read_exact(&mut buf[..2]) {
                Ok(_) => {
                    match buf[0] {
                        5 => {
                            let num = buf[1] as usize;
                            match inbound.read_exact(&mut buf[2..2 + num]) {
                                Ok(_) => {
                                    match buf[2..2 + num].iter().find(|&&x| x == 0) {
                                        Some(_) => {
                                            match inbound.write(&[5, 0]) {
                                                Ok(_) => true,
                                                Err(_) => false,
                                            }
                                        }
                                        None => false,
                                    }
                                }
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    }
                }
                Err(_) => false,
            }
        }

        fn read_request(&mut self) -> Option<SocksRequest> {
            let mut buf = vec![0;300];
            let inbound = Arc::get_mut(&mut self.inbound).unwrap();
            match inbound.read(&mut buf[..]) {
                Ok(n) => {
                    println!("n={}", n);
                    match n {
                        n if n > 4 => {
                            let mut req = SocksRequest::new();
                            req.cmd = match buf[1] {
                                1 => Cmd::Connect,
                                2 => Cmd::Bind,
                                3 => Cmd::UdpAssociate,
                                _ => return None,
                            };

                            let (addr, alen) = match buf[3] {
                                1 => {
                                    match n {
                                        n if n >= 10 => {
                                            let mut p = [0u8; 4];
                                            p.copy_from_slice(&buf[4..8]);
                                            (Addr::IPv4(Ipv4Addr::from(p)), 4)
                                        }
                                        _ => return None,
                                    }
                                }
                                3 => {
                                    match n {
                                        n if n >= 4 + (buf[4] as usize) + 2 => {
                                            let domain =
                                                String::from_utf8_lossy(&buf[5..5 +
                                                                                (buf[4] as usize)])
                                                    .into_owned();
                                            (Addr::Domain(domain), buf[4] as usize + 1)
                                        }
                                        _ => return None,
                                    }
                                }
                                4 if n >= 22 => {
                                    let mut p = [0u8; 16];
                                    p.copy_from_slice(&buf[4..20]);
                                    (Addr::IPv6(Ipv6Addr::from(p)), 16)
                                }
                                _ => return None,
                            };
                            req.addr = addr;
                            req.port = (buf[4 + alen] as u32) * 256 + buf[4 + alen + 1] as u32;
                            Some(req)
                        }
                        _ => None,

                    }
                }
                Err(e) => None,
            }
        }

        fn write_resp(&mut self, code: u8, addr: Option<SocketAddr>) {
            let mut buf = vec![];
            buf.push(5);
            buf.push(code);
            buf.push(0);
            let (atype, mut baddr, mut bport) = match addr {
                Some(SocketAddr::V4(ip)) => {
                    (1,
                     Vec::from(&ip.ip().octets()[..]),
                     vec![(ip.port() >> 8 & 0xff) as u8, (ip.port() & 0xff) as u8])
                }
                Some(SocketAddr::V6(ip)) => {
                    (4,
                     Vec::from(&ip.ip().octets()[..]),
                     vec![(ip.port() >> 8 & 0xff) as u8, (ip.port() & 0xff) as u8])
                }
                None => (1, vec![0;4], vec![0;2]),
            };
            buf.push(atype);
            buf.append(&mut baddr);
            buf.append(&mut bport);
            println!("write resp {:?}", buf);
            let inbound = Arc::get_mut(&mut self.inbound).unwrap();
            inbound.write(&buf.as_slice());
            inbound.flush();
        }
    }

    for sock in server.incoming() {
        match sock {
            Ok(sock) => {

                println!("connection from {}", sock.peer_addr().unwrap());
                thread::spawn(move || Session::new(sock).start());
            }
            Err(e) => {
                println!("accept {}", e);
            }
        }
    }
}
