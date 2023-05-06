use std::{
    convert::TryInto,
    fs::{create_dir_all, File},
};

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use futures::future::join_all;
use hp_distributed::{
    config::{CIRCUIT_CONFIG, DATA_DIR, WORKERS},
    dispatcher::HyperPlonk,
    mock::MockCircuit,
    storage::SliceStorage,
    worker::{Method, Status},
};
use hyperplonk::prelude::CustomizedGates;
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

    let jf_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
    let circuit = MockCircuit::<Fr>::new(rng, 1 << CIRCUIT_CONFIG.custom_nv, &jf_gate);
    SliceStorage::new(DATA_DIR.join("dispatcher/circuit.inputs.bin"))
        .store(&circuit.public_inputs)?;

    let pcs_srs = HyperPlonk::universal_setup(SUPPORTED_SIZE, rng);

    let mut workers = join_all(WORKERS.iter().map(|worker| async move {
        let stream = StubbornTcpStream::connect(worker).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }))
    .await;

    let vk = HyperPlonk::key_gen_async(&mut workers, seed, pcs_srs).await;

    for i in &vk.selector_commitments {
        println!("{}", i.0);
    }
    for i in &vk.perm_commitments {
        println!("{}", i.0);
    }

    vk.serialize_uncompressed(File::create(DATA_DIR.join("dispatcher/vk.bin"))?)?;
    Ok(())
}
