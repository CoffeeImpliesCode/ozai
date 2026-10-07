//! Capture emitted messages from the pinned upstream IO-less Gossip state machine.
use std::{collections::{BTreeMap, VecDeque}, path::PathBuf};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use iroh_gossip::proto::{Command, Config, InEvent, Message, OutEvent, PeerData, Scope, State, Timer, TopicId};
use n0_future::time::{Duration, Instant};
use rand::{SeedableRng, rngs::ChaCha12Rng};

const COMMIT: &str = "2885dd9f1120e46aca5acbcd7f212e4c64e278b9";
const NAMES: [&str; 10] = ["join", "forward_join", "shuffle", "shuffle_reply", "neighbor", "disconnect", "gossip", "prune", "graft", "ihave"];
type Peer = [u8; 32];
type Node = State<Peer, ChaCha12Rng>;

struct Driver {
    nodes: Vec<Node>,
    topic: TopicId,
    now: Instant,
    queue: VecDeque<(usize, InEvent<Peer>)>,
    timers: Vec<(Instant, usize, Timer<Peer>)>,
    captures: BTreeMap<String, Vec<u8>>,
    provenance: BTreeMap<String, String>,
    first_gossip: Option<(usize, usize, Message<Peer>)>,
    drop_gossip_to: Option<usize>,
    events: usize,
}

fn peer(index: usize) -> Peer {
    *iroh::SecretKey::from_bytes(&[index as u8 + 1; 32]).public().as_bytes()
}

// The two discriminants identify an actual serialized upstream enum, not a
// locally constructed wire variant. All returned frames originate in SendMessage.
fn variant(body: &[u8]) -> Result<usize> {
    ensure!(body.len() >= 2, "upstream message has no nested discriminator");
    match (body[0], body[1]) {
        (0, inner @ 0..=5) => Ok(inner as usize),
        (1, inner @ 0..=3) => Ok(inner as usize + 6),
        _ => anyhow::bail!("unknown upstream discriminators"),
    }
}

fn framed(body: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(body.len())?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

impl Driver {
    fn new() -> Self {
        let mut config = Config::default();
        config.membership.active_view_capacity = 16;
        config.membership.active_random_walk_length.0 = 0;
        config.membership.shuffle_random_walk_length.0 = 0;
        config.membership.shuffle_active_view_count = 10;
        config.membership.shuffle_interval = Duration::from_millis(200);
        let nodes = (0..12).map(|i| State::new(
            peer(i), PeerData::new(vec![0xa0 + i as u8; 300]),
            config.clone(), ChaCha12Rng::seed_from_u64(0x2885dd9 + i as u64),
        )).collect();
        Self {
            nodes, topic: TopicId::from([0x74; 32]), now: Instant::now(),
            queue: VecDeque::new(), timers: Vec::new(), captures: BTreeMap::new(),
            provenance: BTreeMap::new(), first_gossip: None,
            drop_gossip_to: None, events: 0,
        }
    }

    fn command(&mut self, node: usize, command: Command<Peer>) -> Result<()> {
        self.queue.push_back((node, InEvent::Command(self.topic, command)));
        self.pump()
    }

    fn capture(&mut self, name: &str, bytes: Vec<u8>, description: String) {
        // Canonical minimum removes dependence on peer-set output iteration order.
        let replace = self.captures.get(name).is_none_or(|old| bytes < *old);
        if replace {
            self.captures.insert(name.to_owned(), bytes);
            self.provenance.insert(name.to_owned(), description);
        }
    }

    fn pump(&mut self) -> Result<()> {
        while let Some((from, event)) = self.queue.pop_front() {
            self.events += 1;
            ensure!(self.events < 500_000, "state driver exceeded bounded event count");
            let emitted: Vec<_> = self.nodes[from].handle(event, self.now, None).collect();
            for event in emitted {
                match event {
                    OutEvent::SendMessage(to, message) => {
                        let target = self.nodes.iter().position(|node| *node.me() == to)
                            .context("state emitted an unknown peer")?;
                        let encoded = postcard::to_stdvec(&message)?;
                        let header = postcard::to_stdvec(&self.topic)?;
                        ensure!(encoded.starts_with(&header), "state message TopicId prefix changed");
                        let body = &encoded[header.len()..];
                        let kind = variant(body)?;
                        let name = NAMES[kind];
                        let description = format!("from={} to={} emitted={message:?}", from + 1, target + 1);
                        self.capture(name, framed(body)?, description.clone());
                        // Boundary captures are also actual emitted upstream frames.
                        if kind == 0 { self.capture("peer_data_300", framed(body)?, description.clone()); }
                        if kind == 2 && body.get(34).is_some_and(|n| *n >= 9) {
                            self.capture("shuffle_large", framed(body)?, description.clone());
                        }
                        if kind == 6 {
                            self.capture("gossip_large", framed(body)?, description.clone());
                            if self.first_gossip.is_none() {
                                self.first_gossip = Some((from, target, message.clone()));
                            }
                        }
                        if kind == 9 && body.get(2).is_some_and(|n| *n >= 17) {
                            self.capture("ihave_large", framed(body)?, description);
                        }
                        if kind != 6 || self.drop_gossip_to != Some(target) {
                            self.queue.push_back((target, InEvent::RecvMessage(peer(from), message)));
                        }
                    }
                    OutEvent::ScheduleTimer(delay, timer) => self.timers.push((self.now + delay, from, timer)),
                    OutEvent::DisconnectPeer(_) | OutEvent::EmitEvent(_, _) | OutEvent::PeerData(_, _) => {}
                }
            }
        }
        Ok(())
    }

    fn advance(&mut self, duration: Duration) -> Result<()> {
        let until = self.now + duration;
        loop {
            let next = self.timers.iter().enumerate()
                .filter(|(_, timer)| timer.0 <= until)
                .min_by_key(|(sequence, timer)| (timer.0, *sequence))
                .map(|(index, _)| index);
            let Some(index) = next else { break; };
            let (at, node, timer) = self.timers.remove(index);
            self.now = at;
            self.queue.push_back((node, InEvent::TimerExpired(timer)));
            self.pump()?;
        }
        self.now = until;
        Ok(())
    }

    fn drive(&mut self) -> Result<()> {
        for node in 0..self.nodes.len() { self.command(node, Command::Join(vec![]))?; }
        for node in 1..self.nodes.len() { self.command(node, Command::Join(vec![peer(0)]))?; }
        self.advance(Duration::from_millis(250))?;
        self.command(0, Command::Broadcast(Bytes::from(vec![0x42; 2048]), Scope::Swarm))?;
        let (from, to, message) = self.first_gossip.clone().context("no Gossip was emitted")?;
        // Duplicate a real emitted packet: receiver Prunes the sender, making the
        // edge lazy. Later drop eager data to that receiver to exercise IHave/Graft.
        self.queue.push_back((to, InEvent::RecvMessage(peer(from), message)));
        self.pump()?;
        self.drop_gossip_to = Some(to);
        for value in 0..20u8 {
            self.command(from, Command::Broadcast(Bytes::from(vec![value; 2048]), Scope::Swarm))?;
        }
        self.advance(Duration::from_secs(3))?;
        self.drop_gossip_to = None;
        self.command(0, Command::Quit)?;
        for name in NAMES { ensure!(self.captures.contains_key(name), "driver did not emit {name}"); }
        for name in ["peer_data_300", "gossip_large", "ihave_large", "shuffle_large"] {
            ensure!(self.captures.contains_key(name), "driver did not emit boundary vector {name}");
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let output = std::env::args_os().nth(1).map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../src/gossip/fixtures/iroh-2885dd9"));
    let mut driver = Driver::new();
    for index in 0..driver.nodes.len() {
        let actual_id = iroh::SecretKey::from_bytes(&[index as u8 + 1; 32]).public();
        ensure!(
            postcard::to_stdvec(&actual_id)? == postcard::to_stdvec(&peer(index))?,
            "PI serialization differs from production EndpointId"
        );
    }
    ensure!(postcard::to_stdvec(&driver.topic)?.len() == 32, "TopicId wire prefix changed");
    driver.drive()?;
    std::fs::create_dir_all(&output)?;
    let header = framed(&postcard::to_stdvec(&driver.topic)?)?;
    std::fs::write(output.join("header.bin"), header)?;
    let mut provenance = format!(
        "Captured by gossip-vectors from actual proto::State OutEvent::SendMessage.\nupstream=https://github.com/n0-computer/iroh-gossip\ncommit={COMMIT}\npackage=0.101.0\nPI=[u8;32], node i uses Ed25519 public key derived by iroh::SecretKey seed [i+1;32]\ntopic=[0x74;32]\nPeerData(i)=[0xa0+i;300]\nRNG=rand0.10.1 ChaCha12Rng seed 0x2885dd9+i\nconfig=default except active_view_capacity16, active_random_walk_length0, shuffle_random_walk_length0, shuffle_active_view_count10, shuffle_interval200ms\nscheduler=FIFO packets, earliest timer then insertion order; canonical lexicographic minimum per variant\ndriver=12 nodes join empty, nodes1..11 join node0, advance250ms, broadcast2048 bytes 0x42, duplicate actual Gossip, drop eager Gossip to duplicate recipient, broadcast20 payloads of2048 repeated bytes0..19, advance3s, quit node0\nframe=u32BE body length + postcard actual Message minus postcard TopicId prefix; header=u32BE length + postcard TopicId\nevents={}\n", driver.events,
    );
    for (name, bytes) in &driver.captures {
        std::fs::write(output.join(format!("{name}.bin")), bytes)?;
        provenance.push_str(&format!("{name}: frame_bytes={} {}\n", bytes.len(), driver.provenance[name]));
        println!("gossip-vector: {name} bytes {}", bytes.len());
    }
    std::fs::write(output.join("provenance.txt"), provenance)?;
    println!("gossip-vectors: commit {COMMIT}, variants 10, boundary_vectors 4, output {}", output.display());
    Ok(())
}
