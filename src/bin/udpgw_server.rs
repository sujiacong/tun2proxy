use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{
        tcp::{ReadHalf, WriteHalf},
        UdpSocket,
    },
    sync::mpsc::{self, Receiver, Sender},
};
use tun2proxy::{udpgw::*, ArgVerbosity, Result};

pub(crate) const CLIENT_DISCONNECT_TIMEOUT: tokio::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Client {
    addr: SocketAddr,
    last_activity: std::time::Instant,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            last_activity: std::time::Instant::now(),
        }
    }
}

#[derive(Debug, Clone, clap::Parser)]
pub struct UdpGwArgs {
    /// UDP gateway listen address
    #[arg(short, long, value_name = "IP:PORT", default_value = "127.0.0.1:7300")]
    pub listen_addr: SocketAddr,

    /// UDP mtu
    #[arg(short = 'm', long, value_name = "udp mtu", default_value = "10240")]
    pub udp_mtu: u16,

    /// UDP timeout in seconds
    #[arg(short = 't', long, value_name = "seconds", default_value = "3")]
    pub udp_timeout: u64,

    /// Daemonize for unix family or run as Windows service
    #[cfg(unix)]
    #[arg(long)]
    pub daemonize: bool,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
}

impl UdpGwArgs {
    #[allow(clippy::let_and_return)]
    pub fn parse_args() -> Self {
        use clap::Parser;
        Self::parse()
    }
}

async fn send_error(tx: Sender<Vec<u8>>, conn_id: u16) {
    let error_packet: Vec<u8> = Packet::build_error_packet(conn_id).into();
    if let Err(e) = tx.send(error_packet).await {
        log::error!("send error response error {:?}", e);
    }
}

async fn send_keepalive_response(tx: Sender<Vec<u8>>, conn_id: u16) {
    let keepalive_packet: Vec<u8> = Packet::build_keepalive_packet(conn_id).into();
    if let Err(e) = tx.send(keepalive_packet).await {
        log::error!("send keepalive response error {:?}", e);
    }
}

/// Send data field of packet from client to destination server and receive response,
/// then wrap response data to the packet's data field and send packet back to client.
async fn process_udp(addr: SocketAddr, udp_timeout: u64, tx: Sender<Vec<u8>>, mut con: Packet) -> Result<()> {
    use socks5_impl::protocol::AddressType;
    let Some(dst_addr) = &con.address else {
        log::error!("client {} udp request address is None", addr);
        return Ok(());
    };
    let std_sock = if dst_addr.get_type() == AddressType::IPv6 {
        std::net::UdpSocket::bind("[::]:0")?
    } else {
        std::net::UdpSocket::bind("0.0.0.0:0")?
    };
    std_sock.set_nonblocking(true)?;
    #[cfg(unix)]
    nix::sys::socket::setsockopt(&std_sock, nix::sys::socket::sockopt::ReuseAddr, &true)?;
    let socket = UdpSocket::from_std(std_sock)?;
    use std::net::ToSocketAddrs;
    let Some(dst_addr) = dst_addr.to_socket_addrs()?.next() else {
        log::error!("client {} udp request address to_socket_addrs", addr);
        return Ok(());
    };
    // 1. send udp data to destination server
    socket.send_to(&con.data, &dst_addr).await?;
    con.data.resize(2048, 0);
    // 2. receive response from destination server
    match tokio::time::timeout(tokio::time::Duration::from_secs(udp_timeout), socket.recv_from(&mut con.data)).await {
        Ok(ret) => {
            let (len, _addr) = ret?;
            con.data.truncate(len);
            let packet: Vec<u8> = con.into();
            // 3. send response back to client
            if let Err(e) = tx.send(packet).await {
                log::error!("client {} send udp response {}", addr, e);
            }
        }
        Err(e) => {
            log::warn!("client {} udp recv_from {}", addr, e);
        }
    }
    Ok(())
}

async fn process_client_udp_req(args: &UdpGwArgs, tx: Sender<Vec<u8>>, client: Client, mut reader: ReadHalf<'_>) -> std::io::Result<()> {
    let mut client = client;
    let udp_timeout = args.udp_timeout;

    loop {
        // 1. read udp packet from client
        use socks5_impl::protocol::AsyncStreamOperation;
        let res = tokio::time::timeout(tokio::time::Duration::from_secs(2), Packet::retrieve_from_async_stream(&mut reader)).await;
        let packet = match res {
            Ok(Ok(packet)) => packet,
            Ok(Err(e)) => {
                log::error!("client {} retrieve_from_async_stream {}", client.addr, e);
                break;
            }
            Err(_) => {
                if client.last_activity.elapsed() >= CLIENT_DISCONNECT_TIMEOUT {
                    log::debug!("client {} last_activity elapsed", client.addr);
                    break;
                }
                continue;
            }
        };
        client.last_activity = std::time::Instant::now();

        let flags = packet.header.flags;
        let conn_id = packet.header.conn_id;
        if flags & UDPGW_FLAG_KEEPALIVE != 0 {
            log::trace!("client {} send keepalive", client.addr);
            // 2. if keepalive packet, do nothing, send keepalive response to client
            send_keepalive_response(tx.clone(), conn_id).await;
            continue;
        }
        log::trace!("client {} received udp data {}", client.addr, packet);

        // 3. process client udp packet in a new task
        let tx1 = tx.clone();
        let tx2 = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = process_udp(client.addr, udp_timeout, tx1, packet).await {
                send_error(tx2, conn_id).await;
                log::error!("client {} process udp function {}", client.addr, e);
            }
        });
    }
    Ok(())
}

async fn write_to_client(addr: SocketAddr, mut writer: WriteHalf<'_>, mut rx: Receiver<Vec<u8>>) -> std::io::Result<()> {
    loop {
        let Some(udp_response) = rx.recv().await else {
            log::trace!("client {} channel closed", addr);
            break;
        };
        if udp_response.is_empty() {
            log::trace!("client {} channel recv 0", addr);
            break;
        }
        log::trace!("send response to client {} len {}", addr, udp_response.len());
        let _r = writer.write(&udp_response).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arc::new(UdpGwArgs::parse_args());

    let tcp_listener = tokio::net::TcpListener::bind(args.listen_addr).await?;

    let default = format!("{:?}", args.verbosity);

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    log::info!("UDP Gateway Server running at {}", args.listen_addr);

    #[cfg(unix)]
    if args.daemonize {
        let stdout = std::fs::File::create("/tmp/udpgw.out")?;
        let stderr = std::fs::File::create("/tmp/udpgw.err")?;
        let daemonize = daemonize::Daemonize::new()
            .working_directory("/tmp")
            .umask(0o777)
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");
        let _ = daemonize
            .start()
            .map_err(|e| format!("Failed to daemonize process, error:{:?}", e))?;
    }

    loop {
        let (mut tcp_stream, addr) = tcp_listener.accept().await?;
        let client = Client::new(addr);
        log::info!("client {} connected", addr);
        let params = args.clone();
        tokio::spawn(async move {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(100);
            let (tcp_read_stream, tcp_write_stream) = tcp_stream.split();
            let res = tokio::select! {
                v = process_client_udp_req(&params, tx, client, tcp_read_stream) => v,
                v = write_to_client(addr, tcp_write_stream, rx) => v,
            };
            log::info!("client {} disconnected with {:?}", addr, res);
        });
    }
}
