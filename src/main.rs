use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::Parser;

#[derive(Parser)]
#[clap(name = "Simple Http Proxy Server")]
#[clap(author = "Louis Huang. <hml1006@qq.com>")]
#[clap(version = "1.0")]
#[clap(about = "Server listen on port and forward data with http proxy protocol", long_about = None)]
struct Cli {
    #[clap(short = 'h', long, default_value = "0.0.0.0")]
    host: String,
    #[clap(long)]
    port: u16,
    #[clap(short = 'u', long)]
    username: String,
    #[clap(short = 'p', long)]
    password: String
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let username = cli.username;
    let password = cli.password;
    
    let addr = format!("{}:{}", cli.host, cli.port);
    println!("lisen on {}", addr);

    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = [0; 1024];

            // In a loop, read data from the socket and write the data back.
            loop {
                let n = match socket.read(&mut buf).await {
                    // socket closed
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("failed to read from socket; err = {:?}", e);
                        return;
                    }
                };

                // Write the data back
                if let Err(e) = socket.write_all(&buf[0..n]).await {
                    eprintln!("failed to write to socket; err = {:?}", e);
                    return;
                }
            }
        });
    }
}