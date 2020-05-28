#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

use std::io;
use std::net::SocketAddr;

use futures::{Future, Sink, Stream};
use tungstenite::Message;

mod crypto;
mod dtls;
mod error;
mod ice;
mod peer;
mod sdp;
mod stun;
mod udp;
mod util;
mod websocket;

use crate::ice::{Candidate, CandidateType, Ice, Transport};
use crate::peer::PeerConnection;
use crate::sdp::SimpleSession;
use crate::websocket::{ClientMessage, RelayEnvelope, RelayPayload};

static WS_URL: &str = "ws://127.0.0.1:8080/ws";

fn main() {
    // Initialize the logging system, applying a default RUST_LOG if it is not already set.
    if let Err(_) = ::std::env::var("RUST_LOG") {
        ::std::env::set_var("RUST_LOG", "webrtc_demo_client=info,webrtc_sctp=trace");
    }
    env_logger::init();

    // Determine our local non-loopback IPv4 address.
    let args: Vec<String> = ::std::env::args().collect();
    let local_address = if args.len() > 1 {
        match args[1].parse() {
            Ok(ip) => {
                info!("Using user-provided local address: {:?}", ip);
                ip
            }
            Err(_) => panic!("Cannot parse IP address given as command-line argument."),
        }
    } else {
        util::get_local_address()
    };

    // Generate a new private key and self-signed certificate for this session.
    let identity = crypto::Identity::generate().unwrap();
    // Generate a new ICE context for this session.
    let mut ice = Ice::new();

    // single-threaded reactor.
    // TODO: Use new tokio API with multi-threaded reactor.
    use tokio::runtime::current_thread::Runtime;
    let mut rt = Runtime::new().unwrap();
    let handle = rt.handle();

    let url = url::Url::parse(WS_URL).unwrap();
    let client = tokio_tungstenite::connect_async(url)
        .and_then(move |(ws_stream, _)| {
            let (mut sink, stream) = ws_stream.split();
            stream.for_each(move |message| {
                match message {
                    Message::Text(m) => {
                        let message = websocket::parse_message(&m);
                        match message {
                            ClientMessage::Relay(r) => {
                                let peer_name = r.name.clone();
                                let message = match RelayEnvelope::unpack(&r) {
                                    Ok(m) => m,
                                    Err(e) => panic!("error: {}", e),
                                };
                                match message.payload {
                                    RelayPayload::Sdp(ref sdp) => {
                                        if sdp.type_ != "offer" {
                                            panic!("received non-offer SDP");
                                        }
                                        let session: SimpleSession = sdp.sdp.parse().unwrap();
                                        info!("SDP recv:\n{}", session.to_string());
                                        let answer =
                                            session.answer(&identity.fingerprint, &mut ice);
                                        info!("SDP send:\n{}", answer.to_string());
                                        let msg = Message::text(
                                            websocket::encode_answer(&answer, &message, &peer_name)
                                                .unwrap(),
                                        );
                                        // TODO: this returns a future that needs to be driven.
                                        sink.start_send(msg).unwrap();
                                    }
                                    RelayPayload::Ice(ice_msg) => {
                                        let candidate: Candidate =
                                            ice_msg.candidate.parse().unwrap();
                                        info!("ICE: recv candidate: {:?}", candidate);

                                        // HACK: For this demo, we're only looking at "host" type
                                        // candidates -- not the server-reflexive candidates that
                                        // would be needed for NAT traversal.
                                        if candidate.type_ == CandidateType::Host
                                            && candidate.transport == Transport::UDP
                                        {
                                            if let SocketAddr::V4(s) = candidate.address {
                                                info!("Peer IPv4 address: {}", candidate.address);

                                                // HACK: For this same-host demonstration, we can
                                                // just look for the peer IP that matches our IP.
                                                if s.ip() == &local_address {
                                                    ice.candidate = Some(candidate);
                                                    let peer = PeerConnection::new(
                                                        handle.clone(),
                                                        identity.clone(),
                                                        ice.clone(),
                                                    );

                                                    // Provide our ICE candidate to the peer
                                                    let local_candidate = Candidate {
                                                        foundation: "1".to_string(),
                                                        transport: Transport::UDP,
                                                        address: peer.local_address,
                                                        type_: CandidateType::Host,
                                                        username: ice.username.clone(),
                                                    };
                                                    let msg = Message::text(
                                                        websocket::encode_candidate(
                                                            &local_candidate,
                                                            &ice_msg.sdp_mid,
                                                            &peer_name,
                                                        )
                                                        .unwrap(),
                                                    );
                                                    // TODO: this returns a future that needs to be driven.
                                                    sink.start_send(msg).unwrap();

                                                    handle.spawn(peer.map_err(|e| {
                                                        error!("peer connection error: {}", e);
                                                        ()
                                                    })).unwrap();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        warn!("Unsupported WS message received: {:?}", message);
                    }
                };

                Ok(())
            })
        })
        .map_err(|e| {
            error!("Error connecting to websocket: {}", e);
            io::Error::new(io::ErrorKind::Other, e)
        });

    rt.spawn(client.map_err(|_e| ()));
    rt.run().unwrap();
    //tokio::runtime::run(client.map_err(|_e| ()));
}
