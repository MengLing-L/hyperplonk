use std::{
    convert::TryInto,
    fs::{create_dir_all, File},
};

use ark_bls12_381::Bls12_381;
use ark_serialize::CanonicalSerialize;
use futures::future::join_all;
use hp_distributed::{
    config::{DATA_DIR, WORKERS},
    dispatcher::HyperPlonk,
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

const SUPPORTED_SIZE: usize = 10;
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(DATA_DIR.join("dispatcher"))?;

    let mut seed = [0; 32];
    thread_rng().fill_bytes(&mut seed);

    let rng = &mut ChaChaRng::from_seed(seed);

    let pcs_srs = HyperPlonk::universal_setup(SUPPORTED_SIZE, rng);

    let mut workers = join_all(WORKERS.iter().map(|worker| async move {
        let stream = StubbornTcpStream::connect(worker).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }))
    .await;

    HyperPlonk::key_gen_async(&mut workers, seed, pcs_srs).await;

    Ok(())
}
