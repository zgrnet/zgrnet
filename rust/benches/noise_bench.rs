use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use noise::{Config, HandshakeState, Key, KeyPair, Pattern, Session, SessionConfig, SessionManager};
use std::sync::Arc;
use std::thread;

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| b.iter(|| KeyPair::generate()));
}

fn bench_dh(c: &mut Criterion) {
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();

    c.bench_function("dh", |b| b.iter(|| alice.dh(black_box(&bob.public))));
}

fn bench_hash(c: &mut Criterion) {
    let data = [0u8; 64];

    c.bench_function("hash", |b| {
        b.iter(|| noise::cipher::hash(black_box(&[&data[..]])))
    });
}

fn bench_encrypt_1kb(c: &mut Criterion) {
    let key = [0u8; 32];
    let plaintext = [0u8; 1024];

    let mut group = c.benchmark_group("encrypt");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1kb", |b| {
        let mut nonce = 0u64;
        b.iter(|| {
            let result =
                noise::cipher::encrypt(black_box(&key), nonce, black_box(&plaintext), &[]);
            nonce = nonce.wrapping_add(1);
            black_box(result);
        })
    });
    group.finish();
}

fn bench_decrypt_1kb(c: &mut Criterion) {
    let key = [0u8; 32];
    let plaintext = [0u8; 1024];
    let ciphertext = noise::cipher::encrypt(&key, 0, &plaintext, &[]);

    let mut group = c.benchmark_group("decrypt");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1kb", |b| {
        b.iter(|| noise::cipher::decrypt(black_box(&key), 0, black_box(&ciphertext), &[]).unwrap())
    });
    group.finish();
}

fn bench_handshake_ik(c: &mut Criterion) {
    let initiator_static = KeyPair::generate();
    let responder_static = KeyPair::generate();

    c.bench_function("handshake_ik", |b| {
        b.iter(|| {
            let mut initiator = HandshakeState::new(Config {
                pattern: Some(Pattern::IK),
                initiator: true,
                local_static: Some(initiator_static.clone()),
                remote_static: Some(responder_static.public.clone()),
                ..Default::default()
            })
            .unwrap();

            let mut responder = HandshakeState::new(Config {
                pattern: Some(Pattern::IK),
                initiator: false,
                local_static: Some(responder_static.clone()),
                ..Default::default()
            })
            .unwrap();

            let msg1 = initiator.write_message(&[]).unwrap();
            responder.read_message(&msg1).unwrap();
            let msg2 = responder.write_message(&[]).unwrap();
            initiator.read_message(&msg2).unwrap();

            let _ = initiator.split().unwrap();
            let _ = responder.split().unwrap();
        })
    });
}

fn bench_transport_1kb(c: &mut Criterion) {
    let initiator_static = KeyPair::generate();
    let responder_static = KeyPair::generate();

    let mut initiator = HandshakeState::new(Config {
        pattern: Some(Pattern::IK),
        initiator: true,
        local_static: Some(initiator_static),
        remote_static: Some(responder_static.public.clone()),
        ..Default::default()
    })
    .unwrap();

    let mut responder = HandshakeState::new(Config {
        pattern: Some(Pattern::IK),
        initiator: false,
        local_static: Some(responder_static),
        ..Default::default()
    })
    .unwrap();

    let msg1 = initiator.write_message(&[]).unwrap();
    responder.read_message(&msg1).unwrap();
    let msg2 = responder.write_message(&[]).unwrap();
    initiator.read_message(&msg2).unwrap();

    let (mut send_i, _) = initiator.split().unwrap();
    let (_, mut recv_r) = responder.split().unwrap();

    let plaintext = [0u8; 1024];
    let mut ct_buffer = [0u8; 1024 + 16];
    let mut pt_buffer = [0u8; 1024 + 16];

    let mut group = c.benchmark_group("transport");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1kb", |b| {
        b.iter(|| {
            send_i.encrypt_to(black_box(&plaintext), &[], &mut ct_buffer);
            recv_r.decrypt_to(&ct_buffer, &[], &mut pt_buffer).unwrap();
            black_box(&pt_buffer);
        })
    });
    group.finish();
}

// =============================================================================
// Concurrent Session Benchmarks
// =============================================================================

fn bench_concurrent_session_create(c: &mut Criterion) {
    c.bench_function("concurrent_session_create", |b| {
        b.iter(|| {
            let manager: Arc<SessionManager> = Arc::new(SessionManager::new());
            let mut handles = Vec::new();
            
            for _ in 0..4 {
                let m: Arc<SessionManager> = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for _ in 0..100 {
                        let kp = KeyPair::generate();
                        let send_key = Key::new(noise::cipher::hash(&[b"send"]));
                        let recv_key = Key::new(noise::cipher::hash(&[b"recv"]));
                        let session = m.create_session(kp.public.clone(), send_key, recv_key);
                        let idx = session.local_index();
                        m.remove_session(idx);
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        })
    });
}

fn bench_concurrent_handshake(c: &mut Criterion) {
    c.bench_function("concurrent_handshake", |b| {
        b.iter(|| {
            let mut handles = Vec::new();
            
            for _ in 0..4 {
                handles.push(thread::spawn(|| {
                    for _ in 0..100 {
                        let initiator_static = KeyPair::generate();
                        let responder_static = KeyPair::generate();

                        let mut initiator = HandshakeState::new(Config {
                            pattern: Some(Pattern::IK),
                            initiator: true,
                            local_static: Some(initiator_static),
                            remote_static: Some(responder_static.public.clone()),
                            ..Default::default()
                        })
                        .unwrap();

                        let mut responder = HandshakeState::new(Config {
                            pattern: Some(Pattern::IK),
                            initiator: false,
                            local_static: Some(responder_static),
                            ..Default::default()
                        })
                        .unwrap();

                        let msg1 = initiator.write_message(&[]).unwrap();
                        responder.read_message(&msg1).unwrap();
                        let msg2 = responder.write_message(&[]).unwrap();
                        initiator.read_message(&msg2).unwrap();

                        let _ = initiator.split().unwrap();
                        let _ = responder.split().unwrap();
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        })
    });
}

fn bench_concurrent_session_encrypt(c: &mut Criterion) {
    let send_key = Key::new(noise::cipher::hash(&[b"send"]));
    let recv_key = Key::new(noise::cipher::hash(&[b"recv"]));

    let session: Arc<Session> = Arc::new(Session::new(SessionConfig {
        local_index: 1,
        remote_index: 2,
        send_key,
        recv_key,
        remote_pk: Key::default(),
    }));

    let mut group = c.benchmark_group("concurrent_encrypt");
    group.throughput(Throughput::Bytes(1024 * 4 * 100)); // 4 threads * 100 ops
    group.bench_function("1kb_4threads", |b| {
        b.iter(|| {
            // Use scoped threads to avoid thread creation overhead in measurement
            thread::scope(|scope| {
                for _ in 0..4 {
                    let s = &session;
                    scope.spawn(move || {
                        let plaintext = [0u8; 1024];
                        let mut out = [0u8; 1024 + 16]; // Pre-allocated buffer
                        for _ in 0..100 {
                            // Use encrypt_to to avoid Vec allocation
                            let _ = s.encrypt_to(black_box(&plaintext), &mut out);
                        }
                    });
                }
            });
        })
    });
    group.finish();
}

fn bench_concurrent_multi_session(c: &mut Criterion) {
    const NUM_SESSIONS: usize = 100;
    let mut sessions_vec: Vec<Session> = Vec::with_capacity(NUM_SESSIONS);
    
    for i in 0..NUM_SESSIONS {
        let mut send_input = vec![i as u8];
        send_input.extend_from_slice(b"send");
        let mut recv_input = vec![i as u8];
        recv_input.extend_from_slice(b"recv");
        let send_key = Key::new(noise::cipher::hash(&[&send_input[..]]));
        let recv_key = Key::new(noise::cipher::hash(&[&recv_input[..]]));
        sessions_vec.push(Session::new(SessionConfig {
            local_index: i as u32 + 1,
            remote_index: i as u32 + 1001,
            send_key,
            recv_key,
            remote_pk: Key::default(),
        }));
    }

    let mut group = c.benchmark_group("concurrent_multi_session");
    group.throughput(Throughput::Bytes(256 * 4 * 100)); // 4 threads * 100 ops
    group.bench_function("100_sessions_4threads", |b| {
        b.iter(|| {
            thread::scope(|scope| {
                for t in 0..4usize {
                    let sessions = &sessions_vec;
                    scope.spawn(move || {
                        let plaintext = [0u8; 256];
                        let mut out = [0u8; 256 + 16]; // Pre-allocated buffer
                        for i in 0..100usize {
                            let idx = (t * 100 + i) % NUM_SESSIONS;
                            let _ = sessions[idx].encrypt_to(black_box(&plaintext), &mut out);
                        }
                    });
                }
            });
        })
    });
    group.finish();
}

fn bench_session_manager_concurrent(c: &mut Criterion) {
    c.bench_function("session_manager_concurrent", |b| {
        b.iter(|| {
            let manager: Arc<SessionManager> = Arc::new(SessionManager::new());

            // Pre-create some sessions
            for _ in 0..100 {
                let kp = KeyPair::generate();
                let send_key = Key::new(noise::cipher::hash(&[b"send"]));
                let recv_key = Key::new(noise::cipher::hash(&[b"recv"]));
                let _ = manager.create_session(kp.public, send_key, recv_key);
            }

            let mut handles = Vec::new();
            
            for _ in 0..4 {
                let m: Arc<SessionManager> = Arc::clone(&manager);
                handles.push(thread::spawn(move || {
                    for _ in 0..50 {
                        let kp = KeyPair::generate();
                        let send_key = Key::new(noise::cipher::hash(&[b"send"]));
                        let recv_key = Key::new(noise::cipher::hash(&[b"recv"]));

                        // Create
                        let session = m.create_session(kp.public.clone(), send_key, recv_key);
                        // Lookup by index
                        let idx = session.local_index();
                        let _ = m.get_by_index(idx);
                        // Lookup by pubkey
                        let _ = m.get_by_pubkey(&kp.public);
                        // Remove
                        m.remove_session(idx);
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_dh,
    bench_hash,
    bench_encrypt_1kb,
    bench_decrypt_1kb,
    bench_handshake_ik,
    bench_transport_1kb,
    bench_concurrent_session_create,
    bench_concurrent_handshake,
    bench_concurrent_session_encrypt,
    bench_concurrent_multi_session,
    bench_session_manager_concurrent,
);
criterion_main!(benches);
