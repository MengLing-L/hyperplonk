use std::{
    cmp::min, convert::TryInto, fs::create_dir_all, mem::size_of, net::SocketAddr, path::PathBuf,
    sync::Arc,
};

use arithmetic::VirtualPolynomial;
use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use ark_std::One;
use futures::future::join_all;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use stubborn_io::StubbornTcpStream;
use subroutines::{
    pcs,
    poly_iop::{structs::IOPProverState, sum_check::SumCheckProver},
};
use tokio::{
    io,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    join,
    net::TcpListener,
    sync::Mutex,
};

use crate::{
    config::{CIRCUIT_CONFIG, DATA_DIR, IP_NAME_MAP, NUM_WIRE_TYPES, WORKERS},
    // gpu::Domain,
    polynomial::VecPolynomial,
    storage::SliceStorage,
    timer,
    utils::CastSlice,
};
mod build_f_hat;
mod keygen;
mod utils;
mod witness_commit;
mod zero_check;

pub struct PlonkImplInner {
    me: usize,
    data_path: PathBuf,

    ck: SliceStorage,
    w_0: SliceStorage,
    w_1: SliceStorage,
    w_2: SliceStorage,
    w_3: SliceStorage,
    w_4: SliceStorage,

    q_0: SliceStorage,
    q_1: SliceStorage,
    q_2: SliceStorage,
    q_3: SliceStorage,
    q_4: SliceStorage,
    q_5: SliceStorage,

    p_0: SliceStorage,
    p_1: SliceStorage,
    p_2: SliceStorage,
    p_3: SliceStorage,
    p_4: SliceStorage,

    // f_hat: Mutex<VirtualPolynomial<Fr>>,
    f_hat: VirtualPolynomial<Fr>,
}

#[repr(u8)]
#[derive(Clone, Copy, strum::Display, TryFromPrimitive, IntoPrimitive)]
pub enum Method {
    KeyGenPrepare = 0x00,
    KeyGenSetCk = 0x01,
    KeyGenCommit = 0x02,
    WitnessCommit = 0x03,
    BuidFhat = 0x04,
    ZeroCheck = 0x05,
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

        Self {
            me,
            ck: SliceStorage::new(data_path.join("srs.ck.bin")),
            w_0: SliceStorage::new(data_path.join("circuit.w_0.bin")),
            w_1: SliceStorage::new(data_path.join("circuit.w_1.bin")),
            w_2: SliceStorage::new(data_path.join("circuit.w_2.bin")),
            w_3: SliceStorage::new(data_path.join("circuit.w_3.bin")),
            w_4: SliceStorage::new(data_path.join("circuit.w_4.bin")),
            q_0: SliceStorage::new(data_path.join("circuit.q_0.bin")),
            q_1: SliceStorage::new(data_path.join("circuit.q_1.bin")),
            q_2: SliceStorage::new(data_path.join("circuit.q_2.bin")),
            q_3: SliceStorage::new(data_path.join("circuit.q_3.bin")),
            q_4: SliceStorage::new(data_path.join("circuit.q_4.bin")),
            q_5: SliceStorage::new(data_path.join("circuit.q_5.bin")),
            p_0: SliceStorage::new(data_path.join("circuit.p_0.bin")),
            p_1: SliceStorage::new(data_path.join("circuit.p_1.bin")),
            p_2: SliceStorage::new(data_path.join("circuit.p_2.bin")),
            p_3: SliceStorage::new(data_path.join("circuit.p_3.bin")),
            p_4: SliceStorage::new(data_path.join("circuit.p_4.bin")),
            f_hat: VirtualPolynomial::<Fr>::new(CIRCUIT_CONFIG.custom_nv),
            data_path,
        }
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
            Method::KeyGenPrepare => self.keygen_prepare(req, res).await,
            Method::KeyGenSetCk => self.keygen_set_ck(req, res).await,
            Method::KeyGenCommit => self.keygen_commit(req, res).await,
            Method::WitnessCommit => self.witness_commit(req, res).await,
            Method::BuidFhat => self.build_f_hat(req, res).await,
            Method::ZeroCheck => self.zero_check(req, res).await,
        }
    }

    async fn keygen_prepare<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        _: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        self.ck.create()?;
        res.write_u8(Status::Ok as u8).await?;
        res.flush().await?;

        Ok(())
    }

    async fn keygen_set_ck<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let hash = req.read_u64_le().await?;
        let length = req.read_u64_le().await?;
        let mut ck_buf = vec![0u8; length as usize];
        req.read_exact(&mut ck_buf).await?;

        if xxhash_rust::xxh3::xxh3_64(&ck_buf) != hash {
            res.write_u8(Status::HashMismatch as u8).await?;
        } else {
            self.ck.append(&ck_buf)?;
            res.write_u8(Status::Ok as u8).await?;
        }
        res.flush().await?;

        Ok(())
    }

    async fn keygen_commit<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let mut seed = [0u8; 32];
        req.read_exact(&mut seed).await?;

        let circuit = self.init_circuit(seed);

        self.store_w_evals(circuit.witnesses);

        res.write_u8(Status::Ok as u8).await?;
        res.write_all(self.init_and_commit_selectors(circuit.index.selectors).cast()).await?;
        res.write_all(self.init_and_commit_permu(circuit.index.permutation).cast()).await?;
        res.flush().await?;

        Ok(())
    }

    async fn witness_commit<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        res.write_u8(Status::Ok as u8).await?;
        res.write_all(self.init_and_commit_w().cast()).await?;
        res.flush().await?;

        Ok(())
    }

    async fn build_f_hat<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let hash = req.read_u64_le().await?;
        let length = req.read_u64_le().await?;
        let mut r_buf = vec![0u8; length as usize];
        req.read_exact(&mut r_buf).await?;
        if xxhash_rust::xxh3::xxh3_64(&r_buf) != hash {
            res.write_u8(Status::HashMismatch as u8).await?;
        } else {
            let r = r_buf.cast::<Fr>();
            res.write_u8(Status::Ok as u8).await?;
            res.write_u64_le(self.build_f_hat_exact(r, CIRCUIT_CONFIG.custom_nv)).await?;
        }
        res.flush().await?;

        Ok(())
    }

    async fn zero_check<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        mut req: BufReader<R>,
        mut res: BufWriter<W>,
    ) -> io::Result<()> {
        let max_degree = req.read_u64_le().await? as usize;
        let mut challenges: Vec<Option<Fr>> = vec![Some(Fr::one()); CIRCUIT_CONFIG.custom_nv - 1];
        req.read_exact(challenges.cast_mut()).await.unwrap();

        let mut prover_state = IOPProverState::<Fr>::prover_init(&self.f_hat).unwrap();
        prover_state.poly.aux_info.max_degree = max_degree;

        let mut prover_msgs = Vec::with_capacity(prover_state.poly.aux_info.num_variables);

        for i in 0..CIRCUIT_CONFIG.custom_nv {
            let prover_msg =
                self.zero_check_exact(CIRCUIT_CONFIG.custom_nv, &mut prover_state, &challenges);
            prover_msgs.push(prover_msg);
        }

        res.write_u8(Status::Ok as u8).await?;
        res.write_all(prover_msgs.cast()).await?;

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
