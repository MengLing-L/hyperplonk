use std::{fs::File, time::Instant};

use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use futures::future::join_all;
use hp_distributed::{
    config::{DATA_DIR, WORKERS},
    dispatcher::HyperPlonk,
    storage::SliceStorage,
    structs::HyperPlonkVerifyingKey,
};
use stubborn_io::StubbornTcpStream;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open(DATA_DIR.join("dispatcher/vk.bin")).unwrap();
    let vk = HyperPlonkVerifyingKey::<Bls12_381>::deserialize_uncompressed_unchecked(& mut f)?;
    let public_inputs: Vec<Fr> =
        SliceStorage::new(DATA_DIR.join("dispatcher/circuit.inputs.bin")).load()?;

    let mut workers = join_all(WORKERS.iter().map(|worker| async move {
        let stream = StubbornTcpStream::connect(worker).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }))
    .await;
    HyperPlonk::prove_async(&mut workers, &public_inputs).await;
    // for i in 0..10 {
    //     let now = Instant::now();
    //     let proof = Plonk::prove_async(&mut workers, &public_inputs, &vk).await.unwrap();
    //     println!("prove {}: {:?}", i, now.elapsed());
    //     assert!(PlonkKzgSnark::verify::<StandardTranscript>(&vk, &public_inputs, &proof).is_ok());
    // }
    Ok(())
}
