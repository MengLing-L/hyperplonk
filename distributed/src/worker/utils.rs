use std::net::SocketAddr;

use ark_bls12_381::{Fr, G1Projective, G1Affine};
use ark_ec::VariableBaseMSM;
use fn_timer::fn_timer;
use futures::future::join_all;
use stubborn_io::StubbornTcpStream;
use subroutines::pcs::multilinear_kzg::srs::Evaluations;

use super::PlonkImplInner;
use crate::{config::WORKERS, mmap::Mmap, storage::SliceStorage};

impl PlonkImplInner {
    #[fn_timer(format!("vec_to_mmap {name}"))]
    pub fn vec_to_mmap<T>(&self, name: &str, mut data: Vec<T>) -> Mmap<T> {
        let mmap = SliceStorage::new(self.data_path.join(format!("{name}.bin")))
            .store_and_mmap(&data)
            .unwrap();
        data.clear();
        data.shrink_to_fit();
        mmap
    }

    #[fn_timer(format!("slice_to_mmap {name}"))]
    pub fn slice_to_mmap<T>(&self, name: &str, data: &[T]) -> Mmap<T> {
        SliceStorage::new(self.data_path.join(format!("{name}.bin"))).store_and_mmap(data).unwrap()
    }
}

impl PlonkImplInner {
    pub async fn peer(id: usize) -> StubbornTcpStream<&'static SocketAddr> {
        let stream = StubbornTcpStream::connect(&WORKERS[id]).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }

    pub async fn peers() -> Vec<StubbornTcpStream<&'static SocketAddr>> {
        join_all(WORKERS.iter().map(|worker| async move {
            let stream = StubbornTcpStream::connect(worker).await.unwrap();
            stream.set_nodelay(true).unwrap();
            stream
        }))
        .await
    }
}

impl PlonkImplInner {
    #[fn_timer]
    #[inline]
    pub fn commit_polynomial(&self, poly: &[Fr]) -> G1Projective {
        let commit_timer = start_timer!(|| "commit");

        let scalars: Vec<Fr> = poly.to_vec();
        
        let base = self.ck.mmap().unwrap();
        let msm_timer = start_timer!(|| format!(
            "msm of size {}",
            base.len()
        ));
        let commitment = G1Projective::msm_unchecked(&base, scalars.as_slice());
        end_timer!(msm_timer);

        end_timer!(commit_timer);
        commitment
    }
}
