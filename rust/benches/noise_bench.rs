use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use noise::{Config, HandshakeState, KeyPair, Pattern};

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

criterion_group!(
    benches,
    bench_key_generation,
    bench_dh,
    bench_hash,
    bench_encrypt_1kb,
    bench_decrypt_1kb,
    bench_handshake_ik,
    bench_transport_1kb,
);
criterion_main!(benches);
