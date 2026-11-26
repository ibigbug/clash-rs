//! Loopback targets for the Naive Docker tests. Built with standalone rustc.
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

const LARGE: usize = 256 * 1024;
static POSTS: AtomicUsize = AtomicUsize::new(0);

fn http(stream: &mut TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(&mut *stream);
    let mut headers = reader.by_ref().lines();
    let request = headers.next().transpose()?.unwrap_or_default();
    let mut length = 0;
    for line in headers {
        let line = line?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().map_err(io::Error::other)?;
        }
    }
    let body = if request.starts_with("POST /echo ") && length <= LARGE {
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        POSTS.fetch_add(1, Ordering::Relaxed);
        bytes
    } else if request.starts_with("GET /count ") {
        POSTS.load(Ordering::Relaxed).to_string().into_bytes()
    } else {
        return Err(io::Error::other("unexpected fixture request"));
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)
}

fn after_eof(stream: &mut TcpStream, size: usize) -> io::Result<()> {
    let mut bytes = Vec::new();
    // The extra byte makes a matching upload wait for EOF before we reply.
    stream.take(size as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.into_iter().ne((0..size).map(|i| (i % 251) as u8)) {
        return Err(io::Error::other("upload contents differ"));
    }
    stream.write_all(&[0xa5; LARGE])
}

fn listen_tcp(
    port: u16,
    handle: impl Fn(&mut TcpStream) -> io::Result<()> + Copy + Send + 'static,
) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream?;
            thread::spawn(move || {
                if let Err(error) = handle(&mut stream) {
                    eprintln!("TCP target {port}: {error}");
                }
            });
        }
        Ok::<_, io::Error>(())
    });
    Ok(())
}

fn main() -> io::Result<()> {
    listen_tcp(10080, http)?;
    for (port, size) in [(10003, 0), (10004, 7), (10005, LARGE)] {
        listen_tcp(port, move |stream| after_eof(stream, size))?;
    }
    for port in [10090, 10091] {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))?;
        thread::spawn(move || -> io::Result<()> {
            let mut bytes = [0; 65535];
            loop {
                let (n, peer) = socket.recv_from(&mut bytes)?;
                socket.send_to(&bytes[..n], peer)?;
            }
        });
    }
    println!("naive targets ready");
    loop {
        thread::park();
    }
}
