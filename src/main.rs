#[macro_use]
extern crate lazy_static;

use std::net::{SocketAddr};
use std::sync::Mutex;
use std::error::Error;
use bytes::BytesMut;

use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::{Arg, Command};
use tokio::io;

const BUF_LEN: usize = 4096;

lazy_static!{
    static ref USERNAME: Mutex<String> = Mutex::new(String::new());
    static ref PASSWORD: Mutex<String> = Mutex::new(String::new());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("Simple Http Proxy Server")
                        .version("1.0")
                        .author("Louis Huang <hml1006@qq.com>")
                        .about("This program is a simple http proxy server, just forward client connection to destination")
                        .arg(Arg::new("address")
                                    .short('a')
                                    .long("addr")
                                    .help("listen address, default is 0.0.0.0")
                                    .takes_value(true)
                                    .default_value("0.0.0.0"))
                        .arg(Arg::new("port")
                                    .short('p')
                                    .long("port")
                                    .help("listen port, default is 8080")
                                    .takes_value(true)
                                    .default_value("8080"))
                        .arg(Arg::new("username")
                                    .short('u')
                                    .long("username")
                                    .help("set a username if you want")
                                    .requires("password")
                                    .takes_value(true)
                                    .default_value("louis"))
                        .arg(Arg::new("password")
                                    .short('w')
                                    .long("password")
                                    .help("set a password if have username")
                                    .requires("username")
                                    .takes_value(true)
                                    .default_value("123"))
                        .get_matches();

    let address = matches.value_of("address").unwrap();
    let port = matches.value_of("port").expect("Should have a listen port");
    let port = port.parse::<i32>().expect("port should be a number");
    if port <= 0 || port > 65535 {
        panic!("port range is (1, 65535)");
    }

    // maybe none
    let username = matches.value_of("username").unwrap_or("").to_string();
    let password = matches.value_of("password").unwrap_or("").to_string();
    if username.len() > 0 && password.len() == 0 {
        panic!("password should not empty");
    }
    
    let addr = if address.contains(":") {
        format!("[{}]:{}", address, port)  // ipv6
    } else {
        format!("{}:{}", address, port)     // ipv4
    };

    let socket_addr: SocketAddr = addr.parse().expect("parse listen address failed");

    println!("lisen on {}", &addr);
    // println!("username: {}   password: {}", username, password);
    *USERNAME.lock().unwrap() = username;
    *PASSWORD.lock().unwrap() = password;

    let listener = TcpListener::bind(socket_addr).await?;

    loop {
        let (socket, _) = listener.accept().await?;
        // deal with client
        tokio::spawn(async move {
            if let Err(err) = deal_client_connect(socket).await {
                println!("{}", err);
            }
        });
    }
}
enum State {
    Established,
    Unauthorized
}

async fn deal_client_connect(mut client: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut head_buf = BytesMut::with_capacity(BUF_LEN);
    let resp_state;
    let path;
    
    // read CONNECT method from client
    loop {
        let mut buf = [0; BUF_LEN];
        let _n = match client.read(&mut buf).await {
            // socket closed
            Ok(n) if n == 0 => {
                println!("socket closed => {:?}", client);
                return Ok(());
            },
            Ok(n) => n,
            Err(e) => {
                println!("failed to read from socket; err = {:?}", e);
                return Err(e.into());
            }
        };
        head_buf.extend_from_slice(&buf);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let parse_ret = req.parse(&head_buf);
        if parse_ret.is_err() {
            println!("Err => {}", parse_ret.err().unwrap());
            return Err(parse_ret.err().unwrap().into());
        }
        let ok_ret = parse_ret.ok().unwrap();
        if ok_ret.is_complete() {
            // check CONNECT method
            if !(req.method.is_some() && req.method.unwrap().to_uppercase() == "CONNECT") {
                return Err("Wrong method".into());
            }
            if req.path.is_none() {
                return Err("path is none".into());
            }
            path = req.path.unwrap();
            if !USERNAME.lock().unwrap().is_empty() {
                // find Proxy-Authorization
                let mut basic_str = BytesMut::new();
                let found_auth = req.headers.iter().any(|header| {
                    if header.name.to_lowercase() == "proxy-authorization" {
                        basic_str.extend_from_slice(header.value);
                        true
                    } else { false }
                });
                if found_auth && !basic_str.is_empty() && check_auth(&basic_str) {
                    resp_state = State::Established;
                } else {
                    resp_state = State::Unauthorized;
                }
            } else {
                resp_state = State::Established;
            }
            break;
        }
    }
    
    // deal response
    let ret = match resp_state {
        State::Established => {
            client.write_all(b"HTTP/1.0 200 Connection Established\r\n\r\n").await
        }
        State::Unauthorized => {
            client.write_all(b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: Basic realm=\"Access to the remote site\"\r\n\r\n").await
        }
    };
    if ret.is_err() {
        return Err(ret.unwrap_err().into());
    }
    let remote_addr_list: Vec<SocketAddr> = tokio::net::lookup_host(path).await?.collect();
    if remote_addr_list.len() == 0 {
        return Err("Lookup host failed".into());
    }
    let remote = TcpStream::connect(remote_addr_list.get(0).unwrap()).await?;
    println!("proxy    {} --- {} <=====> {} --- {}", &client.peer_addr().unwrap().to_string(), &client.local_addr().unwrap().to_string(),
             &remote.local_addr().unwrap().to_string(), &remote.peer_addr().unwrap().to_string());
    forward(client, remote).await;

    Ok(())
}

async fn forward(client: TcpStream, remote: TcpStream) {
    let (client_in, client_out) = client.into_split();
    let (remote_in, remote_out) = remote.into_split();

    tokio::spawn(async move {
        let mut in_stream = client_in;
        let mut out_stream = remote_out;
        let ret = io::copy(&mut in_stream, &mut out_stream).await;
        if ret.is_err() {
            println!("{:?}", ret.unwrap_err());
        }
    });

    tokio::spawn(async move {
        let mut in_stream = remote_in;
        let mut out_stream = client_out;
        let ret = io::copy(&mut in_stream, &mut out_stream).await;
        if ret.is_err() {
            println!("{:?}", ret.unwrap_err());
        }
    });
}

fn check_auth(base64_data: &[u8]) -> bool {
    let basic_str = String::from_utf8_lossy(base64_data);
    let split: Vec<&str> = basic_str.split(" ").collect();
    if split.len() != 2 {
        return false;
    }
    let data = base64::decode(&split[1]);
    if data.is_err() {
        println!("decode base64 failed {}, err => {:?}", split[1], data.err());
    } else {
        let data = data.unwrap();
        let data = String::from_utf8(data);
        if data.is_err() {
            println!("unwrap decoded data error {:?}, err => {:?}", base64_data, data.err());
        } else {
            let data = data.unwrap();
            let user_pass: Vec<&str> = data.split(":").collect();
            if user_pass.len() != 2 {
                println!("wrong username and password format {}", data);
            } else {
                // println!("decode => user: {}, password: {}", user_pass[0], user_pass[1]);
                return *USERNAME.lock().unwrap() == user_pass[0] && *PASSWORD.lock().unwrap() == user_pass[1];
            }
        }
    }

    false
}