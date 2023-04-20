use std::{
    cmp::min, convert::TryInto, fs::create_dir_all, mem::size_of, net::SocketAddr, path::PathBuf,
    sync::Arc,
};

use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use futures::future::join_all;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use stubborn_io::StubbornTcpStream;
use tokio::{
    io,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    join,
    net::TcpListener,
    sync::Mutex,
};

use crate::{
    config::{DATA_DIR, IP_NAME_MAP, NUM_WIRE_TYPES, WORKERS},
    // gpu::Domain,
    polynomial::VecPolynomial,
    storage::SliceStorage,
    timer,
    utils::CastSlice,
};

mod utils;

enum Selectors {
    Type1 { a: SliceStorage, h: SliceStorage },
    Type2 { a: SliceStorage, h: SliceStorage, m: SliceStorage },
    Type3 { o: SliceStorage, c: SliceStorage, e: SliceStorage },
}

pub struct PlonkImplInner {
    me: usize,
    data_path: PathBuf,
}

#[repr(u8)]
#[derive(Clone, Copy, strum::Display, TryFromPrimitive, IntoPrimitive)]
pub enum Method {
    Holleworld = 0x00,
}

#[repr(u8)]
#[derive(Clone, Copy, strum::Display, TryFromPrimitive, IntoPrimitive)]
pub enum Status {
    Ok = 0x00,
    HashMismatch = 0x01,
}

pub struct Worker {
    inner: Arc<PlonkImplInner>,
}

impl PlonkImplInner {
    fn new(me: usize) -> Self {
        let data_path = DATA_DIR.join(format!("worker{}", me));

        create_dir_all(&data_path).unwrap();

        Self { me, data_path }
    }
}

impl PlonkImplInner {
    async fn handle<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        method: Method,
        req: BufReader<R>,
        res: BufWriter<W>,
    ) -> io::Result<()> {
        match method {
            Method::Holleworld => self.holleworld(req, res).await,
        }
    }

    async fn holleworld<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }
}

impl Worker {
    pub fn new(me: usize) -> Self {
        Self { inner: Arc::new(PlonkImplInner::new(me)) }
    }

    pub async fn start(&self) -> io::Result<()> {
        let my_addr = WORKERS[self.inner.me];
        let my_name = IP_NAME_MAP.get(&my_addr.ip()).unwrap();

        let listener = TcpListener::bind(my_addr).await?;

        println!("{} listening on: {}", my_name, my_addr);

        while let Ok((mut stream, addr)) = listener.accept().await {
            let peer_addr = addr.ip();
            if IP_NAME_MAP.contains_key(&peer_addr) {
                let peer_name = IP_NAME_MAP.get(&peer_addr).unwrap();
                println!("{} ({}) connected", peer_name, peer_addr);
                stream.set_nodelay(true)?;
                let this = self.inner.clone();
                tokio::spawn(async move {
                    loop {
                        let (read, write) = stream.split();

                        let mut req = BufReader::new(read);
                        let res = BufWriter::new(write);
                        match req.read_u8().await {
                            Ok(method) => {
                                let method: Method = method.try_into().unwrap();
                                timer!(format!("{} -> {}: {}", peer_name, my_name, method), {
                                    this.handle(method, req, res).await?;
                                });
                            }
                            Err(_) => {
                                println!("{} ({}) disconnected", peer_name, peer_addr);
                                break;
                            }
                        }
                    }
                    Ok::<(), io::Error>(())
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test01() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(async {
            Worker::new(0).start().await.unwrap();
        });
        Worker::new(1).start().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test23() -> Result<(), Box<dyn std::error::Error>> {
        tokio::spawn(async {
            Worker::new(2).start().await.unwrap();
        });
        Worker::new(3).start().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test4() -> Result<(), Box<dyn std::error::Error>> {
        Worker::new(4).start().await?;
        Ok(())
    }
}
