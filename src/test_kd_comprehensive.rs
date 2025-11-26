use pyo3::Python;
use pineapple::{kyber_dilithium, network_kd};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== COMPREHENSIVE KD DEBUG TEST ===\n");

    unsafe {
        std::env::set_var(
            "PYTHONPATH",
            std::env::current_dir()
                .unwrap()
                .join("libs")
                .to_str()
                .unwrap(),
        );
    }

    // Test 1: Basic handshake
    println!("Test 1: Basic handshake...");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("  Listener on port {}", port);

    let listener_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        println!("  [LISTENER] Connected!");

        let my_data = Python::with_gil(|py| {
            kyber_dilithium::kd_init_handshake(py).expect("KD init")
        });

        let theirs: kyber_dilithium::KDHandshakeData =
            network_kd::recv_json(&mut stream).expect("recv peer");
        println!("  [LISTENER] Received peer data");

        network_kd::send_json(&mut stream, &my_data).expect("send self");
        println!("  [LISTENER] Sent my data");

        let kd_session = Python::with_gil(|py| {
            let (ciphertext, shared) =
                kyber_dilithium::kd_process_handshake(py, &theirs).expect("process");
            println!("  [LISTENER] Processed handshake, shared: {} bytes", shared.len());

            network_kd::send_json(&mut stream, &ciphertext).expect("send ct");
            println!("  [LISTENER] Sent ciphertext");

            kyber_dilithium::KDSession::new(&shared)
        });

        (kd_session, stream)
    });

    thread::sleep(Duration::from_millis(100));

    let mut conn_stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    println!("  [CONNECTOR] Connected!");

    let my_data = Python::with_gil(|py| {
        kyber_dilithium::kd_init_handshake(py).expect("KD init")
    });

    network_kd::send_json(&mut conn_stream, &my_data).expect("send self");
    println!("  [CONNECTOR] Sent my data");

    let theirs: kyber_dilithium::KDHandshakeData =
        network_kd::recv_json(&mut conn_stream).expect("recv peer");
    println!("  [CONNECTOR] Received peer data");

    let ciphertext: Vec<u8> =
        network_kd::recv_json(&mut conn_stream).expect("recv ct");
    println!("  [CONNECTOR] Received ciphertext");

    let conn_session = Python::with_gil(|py| {
        let shared = kyber_dilithium::kd_finish_handshake(
            py,
            ciphertext,
            my_data.kyber_sk.clone(),
        )
        .expect("finish");
        println!("  [CONNECTOR] Finished handshake, shared: {} bytes", shared.len());

        kyber_dilithium::KDSession::new(&shared)
    });

    let (listener_session, mut listener_stream) = listener_handle.join().unwrap();

    println!("✅ Handshake complete\n");

    // Test 2: Single message exchange
    println!("Test 2: Single message L->C...");
    let msg = b"Test from listener";
    let ct = listener_session.encrypt(msg).expect("encrypt");
    println!("  [LISTENER] Encrypted: {} bytes", ct.len());

    network_kd::send_json(&mut listener_stream, &ct).expect("send");
    println!("  [LISTENER] Sent");

    let received_ct: Vec<u8> = network_kd::recv_json(&mut conn_stream).expect("recv");
    println!("  [CONNECTOR] Received: {} bytes", received_ct.len());

    let pt = conn_session.decrypt(&received_ct).expect("decrypt");
    println!("  [CONNECTOR] Decrypted: {}", String::from_utf8_lossy(&pt));

    assert_eq!(msg.as_slice(), pt.as_slice());
    println!("✅ L->C working\n");

    // Test 3: Reverse direction
    println!("Test 3: Single message C->L...");
    let msg = b"Test from connector";
    let ct = conn_session.encrypt(msg).expect("encrypt");
    println!("  [CONNECTOR] Encrypted: {} bytes", ct.len());

    network_kd::send_json(&mut conn_stream, &ct).expect("send");
    println!("  [CONNECTOR] Sent");

    let received_ct: Vec<u8> = network_kd::recv_json(&mut listener_stream).expect("recv");
    println!("  [LISTENER] Received: {} bytes", received_ct.len());

    let pt = listener_session.decrypt(&received_ct).expect("decrypt");
    println!("  [LISTENER] Decrypted: {}", String::from_utf8_lossy(&pt));

    assert_eq!(msg.as_slice(), pt.as_slice());
    println!("✅ C->L working\n");

    // Test 4: Multiple rapid messages
    println!("Test 4: Multiple rapid messages...");
    for i in 0..5 {
        let msg = format!("Message {}", i);
        let ct = listener_session.encrypt(msg.as_bytes()).unwrap();
        network_kd::send_json(&mut listener_stream, &ct).unwrap();
        println!("  [LISTENER] Sent message {}", i);

        let received: Vec<u8> = network_kd::recv_json(&mut conn_stream).unwrap();
        let pt = conn_session.decrypt(&received).unwrap();
        let received_msg = String::from_utf8(pt).unwrap();
        println!("  [CONNECTOR] Received: {}", received_msg);
        assert_eq!(msg, received_msg);
    }
    println!("✅ Multiple messages working\n");

    // Test 5: Stream cloning
    println!("Test 5: Testing stream cloning...");
    let mut stream1 = listener_stream.try_clone().unwrap();
    let mut stream2 = listener_stream;

    let msg1 = b"Via stream1";
    let ct1 = listener_session.encrypt(msg1).unwrap();
    network_kd::send_json(&mut stream1, &ct1).unwrap();
    println!("  [LISTENER] Sent via stream1");

    let received: Vec<u8> = network_kd::recv_json(&mut conn_stream).unwrap();
    let pt = conn_session.decrypt(&received).unwrap();
    println!("  [CONNECTOR] Received: {}", String::from_utf8_lossy(&pt));

    let msg2 = b"Via stream2";
    let ct2 = listener_session.encrypt(msg2).unwrap();
    network_kd::send_json(&mut stream2, &ct2).unwrap();
    println!("  [LISTENER] Sent via stream2");

    let received: Vec<u8> = network_kd::recv_json(&mut conn_stream).unwrap();
    let pt = conn_session.decrypt(&received).unwrap();
    println!("  [CONNECTOR] Received: {}", String::from_utf8_lossy(&pt));

    println!("✅ Stream cloning working\n");

    println!("🎉 ALL TESTS PASSED!");
    println!("\nCONCLUSION: The core KD implementation works perfectly.");
    println!("The GUI bug must be in the threading/channel logic.");
}