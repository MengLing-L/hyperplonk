use std::{
    convert::TryInto,
    fs::{create_dir_all, File},
};

use ark_serialize::CanonicalSerialize;
use futures::future::join_all;
use hp_distributed::{
    config::{DATA_DIR, WORKERS},
    storage::SliceStorage,
    worker::{Method, Status},
};
use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use stubborn_io::StubbornTcpStream;
use tokio::{
    io,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    join,
    net::TcpListener,
    sync::Mutex,
};

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(DATA_DIR.join("dispatcher"))?;

    let mut workers = join_all(WORKERS.iter().map(|worker| async move {
        let stream = StubbornTcpStream::connect(worker).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }))
    .await;

    join_all(workers.iter_mut().map(|worker| async move {
        worker.write_u8(Method::Holleworld as u8).await.unwrap();
        worker.flush().await.unwrap();

        match worker.read_u8().await.unwrap().try_into().unwrap() {
            Status::Ok => {
                println!("hello world")
            }
            _ => panic!(),
        }
    }))
    .await;

    Ok(())
}
