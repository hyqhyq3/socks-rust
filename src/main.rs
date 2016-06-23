use std::net::{TcpStream, TcpListener};
use std::thread;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, lookup_host, IpAddr};
use std::io::{Read, Write, Result};
use std::mem::transmute;

fn to_ipv4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn to_ipv6(b: &[u8]) -> Ipv6Addr {
    let mut v = Vec::from(b);
    v.reverse();
    let mut t: &[u16] = unsafe { transmute(&v[..]) };
    Ipv6Addr::new(t[7], t[6], t[5], t[4], t[3], t[2], t[1], t[0])
}

fn main() {
    let server = TcpListener::bind("0.0.0.0:1080").unwrap();

    struct Session {
        inbound: TcpStream,
        outbound: Option<TcpStream>,
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

    impl Session {
        fn new(s: TcpStream) -> Session {
            Session {
                inbound: s,
                outbound: None,
            }
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
                }
                None => (),
            }
        }

        fn dial(&self, a: Addr, p: u32) -> Result<TcpStream> {
            match a {
                Addr::IPv4(e) => TcpStream::connect(SocketAddr::new(IpAddr::V4(e), p as u16)),
                Addr::IPv6(e) => TcpStream::connect(SocketAddr::new(IpAddr::V6(e), p as u16)),
                Addr::Domain(d) => try!(lookup_host(&d)),
            }
        }

        fn handshake(&mut self) -> bool {
            let mut buf = vec![0;257];
            match self.inbound.read_exact(&mut buf[..2]) {
                Ok(_) => {
                    match buf[0] {
                        5 => {
                            let num = buf[1] as usize;
                            match self.inbound.read_exact(&mut buf[2..2 + num]) {
                                Ok(_) => {
                                    match buf[2..2 + num].iter().find(|&&x| x == 0) {
                                        Some(_) => {
                                            match self.inbound.write(&[5, 0]) {
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
            match self.inbound.read(&mut buf[..]) {
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
                                        n if n >= 10 => (Addr::IPv4(to_ipv4(&buf[4..8])), 4),
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
                                4 if n >= 22 => (Addr::IPv6(to_ipv6(&buf[4..20])), 16),
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
