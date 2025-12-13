// Add these to your Cargo.toml dependencies:
// [dependencies]
// eframe = "0.29"
// egui = "0.29"
// tokio = { version = "1", features = ["full"] }
// local-ip-address = "0.6"  // <-- ADD THIS NEW DEPENDENCY
// (keep all your existing dependencies)

use pyo3::Python;
use eframe::egui;
use pineapple::{messages, network, pqxdh, Session};
use std::{
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::SystemTime,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum CryptoMode {
    PQXDH,
    KyberDilithiumAES,
}

// NEW: Function to get local IP address
fn get_local_ip() -> String {
    match local_ip_address::local_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => {
            // Fallback: try to get IP by connecting to a public DNS
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if socket.connect("8.8.8.8:80").is_ok() {
                    if let Ok(addr) = socket.local_addr() {
                        return addr.ip().to_string();
                    }
                }
            }
            "127.0.0.1".to_string() // Last resort fallback
        }
    }
}

fn main() -> Result<(), eframe::Error> {
     unsafe{std::env::set_var("PYTHONPATH", 
        std::env::current_dir()
            .unwrap()
            .join("libs")
            .to_str()
            .unwrap()
    );}
    
    println!("\n╔═══════════════════════════════════════════════════════╗");
    println!("║     PINEAPPLE SECURE MESSENGER - DEBUG MODE          ║");
    println!("╚═══════════════════════════════════════════════════════╝");
    println!("All cryptographic operations and encrypted data will be logged below\n");
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_title("Pineapple - Secure Messaging"),
        ..Default::default()
    };

    eframe::run_native(
        "Pineapple",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(create_whatsapp_theme());
            Ok(Box::new(PineappleApp::default()))
        }),
    )
}

fn create_whatsapp_theme() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    
    visuals.override_text_color = Some(egui::Color32::from_rgb(230, 230, 230));
    visuals.panel_fill = egui::Color32::from_rgb(17, 27, 33);
    visuals.window_fill = egui::Color32::from_rgb(17, 27, 33);
    visuals.extreme_bg_color = egui::Color32::from_rgb(32, 44, 51);
    
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(32, 44, 51);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(32, 44, 51);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(42, 57, 66);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 95, 78);
    
    visuals
}

#[derive(Debug, Clone)]
enum Message {
    Text { content: String, is_sent: bool, timestamp: SystemTime },
    System(String),
}

enum ConnectionState {
    Disconnected,
    Listening(String),
    Connecting,
    Connected,
}

struct PineappleApp {
    state: ConnectionState,
    crypto_mode: CryptoMode,
    messages: Vec<Message>,
    input_text: String,
    connect_address: String,
    
    message_sender: Option<Sender<String>>,
    message_receiver: Arc<Mutex<Option<Receiver<Message>>>>,
    
    running: Arc<AtomicBool>,
    show_copied: bool,
    copied_timer: f32,
}

impl Default for PineappleApp {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            messages: Vec::new(),
            crypto_mode: CryptoMode::PQXDH,
            input_text: String::new(),
            connect_address: String::new(),
            message_sender: None,
            message_receiver: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            show_copied: false,
            copied_timer: 0.0,
        }
    }
}

fn print_hex_dump(label: &str, data: &[u8], max_bytes: usize) {
    let display_len = data.len().min(max_bytes);
    println!("  {} ({} bytes total):", label, data.len());
    println!("    Full hex: {}", hex::encode(&data[..display_len]));
    if data.len() > max_bytes {
        println!("    ... ({} more bytes)", data.len() - max_bytes);
    }
}

impl PineappleApp {
    fn start_listener(&mut self) {
        // CHANGED: Bind to 0.0.0.0 to accept connections from any network interface
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        
        // CHANGED: Get actual local IP instead of 127.0.0.1
        let local_ip = get_local_ip();
        let connection_string = format!("{}:{}", local_ip, port);
        
        println!("\n[LISTENER] Starting listener on {}:{}", local_ip, port);
        println!("[LISTENER] Share this address with your peer: {}", connection_string);
        
        self.state = ConnectionState::Listening(connection_string.clone());
        self.messages
            .push(Message::System(format!("Listening on {}", connection_string)));

        let (tx, rx) = mpsc::channel();
        let (msg_tx, msg_rx) = mpsc::channel();
        self.message_sender = Some(tx);
        *self.message_receiver.lock().unwrap() = Some(msg_rx);

        let running = Arc::clone(&self.running);
        let crypto_mode = self.crypto_mode;

        thread::spawn(move || {
            if let Ok((mut stream, addr)) = listener.accept() {
                println!("[LISTENER] Peer connected from: {}", addr);
                msg_tx.send(Message::System("Peer connected! Establishing secure session...".into())).ok();

                if crypto_mode == CryptoMode::KyberDilithiumAES {
                    println!("\n╔════════════════════════════════════════════════════════╗");
                    println!("║         KYBER-DILITHIUM-AES HANDSHAKE (LISTENER)      ║");
                    println!("╚════════════════════════════════════════════════════════╝");
                    msg_tx.send(Message::System("🔐 Using Kyber768 + Dilithium3 + AES-GCM".into())).ok();

                    println!("\n[STEP 1] Generating Kyber keypair and Dilithium signing keys");
                    println!("─────────────────────────────────────────────────────────");
                    let my_data = Python::with_gil(|py| {
                        pineapple::kyber_dilithium::kd_init_handshake(py).expect("KD init")
                    });
                    println!("✓ Key generation complete");
                    print_hex_dump("Kyber Public Key", &my_data.kyber_pk, 64);
                    print_hex_dump("Kyber Secret Key", &my_data.kyber_sk, 64);
                    print_hex_dump("Dilithium Public Key", &my_data.dilithium_pk, 64);
                    print_hex_dump("Dilithium Secret Key", &my_data.dilithium_sk, 64);

                    println!("\n[STEP 2] Sending our public keys to peer");
                    println!("─────────────────────────────────────────────────────────");
                    pineapple::network_kd::send_json(&mut stream, &my_data).expect("send KD self");
                    println!("✓ Public keys transmitted");

                    println!("\n[STEP 3] Receiving peer's public keys");
                    println!("─────────────────────────────────────────────────────────");
                    let theirs: pineapple::kyber_dilithium::KDHandshakeData =
                        pineapple::network_kd::recv_json(&mut stream).expect("recv KD peer");
                    println!("✓ Peer keys received");
                    print_hex_dump("Peer Kyber Public Key", &theirs.kyber_pk, 64);
                    print_hex_dump("Peer Dilithium Public Key", &theirs.dilithium_pk, 64);

                    println!("\n[STEP 4] Encapsulating shared secret with Kyber");
                    println!("─────────────────────────────────────────────────────────");
                    let (kd_session, ciphertext) = Python::with_gil(|py| {
                        let (ciphertext, shared) =
                            pineapple::kyber_dilithium::kd_process_handshake(py, &theirs)
                                .expect("KD process");
                        
                        println!("✓ Kyber encapsulation complete");
                        print_hex_dump("Kyber Ciphertext", &ciphertext, 64);
                        print_hex_dump("Shared Secret", &shared, 64);
                        println!("  Shared secret strength: {} bits", shared.len() * 8);
                        
                        let session = pineapple::kyber_dilithium::KDSession::new(&shared);
                        println!("✓ AES-GCM session initialized with shared secret");
                        (session, ciphertext)
                    });

                    println!("\n[STEP 5] Sending encapsulated ciphertext");
                    println!("─────────────────────────────────────────────────────────");
                    match pineapple::network_kd::send_json(&mut stream, &ciphertext) {
                        Ok(_) => println!("✓ Ciphertext transmitted successfully"),
                        Err(e) => {
                            println!("✗ FAILED to send ciphertext: {}", e);
                            msg_tx.send(Message::System(format!("ERROR: {}", e))).ok();
                            return;
                        }
                    };

                    println!("\n╔════════════════════════════════════════════════════════╗");
                    println!("║              SESSION ESTABLISHED (LISTENER)            ║");
                    println!("╚════════════════════════════════════════════════════════╝");
                    println!("Encryption: AES-256-GCM");
                    println!("Key Exchange: Kyber768 (ML-KEM)");
                    println!("Authentication: Dilithium3 (ML-DSA)");
                    println!("Ready for encrypted messaging\n");
                    msg_tx.send(Message::System("🔒 Encrypted using AES-GCM".into())).ok();
                    
                    handle_chat_kd(kd_session, stream, rx, msg_tx, running);
                    return;
                }

                // PQXDH path
                println!("\n╔════════════════════════════════════════════════════════╗");
                println!("║              PQXDH HANDSHAKE (LISTENER)                ║");
                println!("╚════════════════════════════════════════════════════════╝");
                
                println!("\n[STEP 1] Generating PQXDH keys");
                println!("─────────────────────────────────────────────────────────");
                let alice = pqxdh::User::new();
                println!("✓ Keys generated (ML-KEM-1024 + X25519)");

                println!("\n[STEP 2] Sending public key bundle");
                println!("─────────────────────────────────────────────────────────");
                if let Err(e) = send_public_keys(&mut stream, &alice) {
                    println!("✗ Handshake failed: {}", e);
                    msg_tx.send(Message::System("Handshake failed".into())).ok();
                    return;
                }
                println!("✓ Public keys transmitted");

                println!("\n[STEP 3] Receiving peer's public keys");
                println!("─────────────────────────────────────────────────────────");
                let mut bob = match receive_public_keys(&mut stream) {
                    Ok(b) => {
                        println!("✓ Peer keys received");
                        b
                    }
                    Err(e) => {
                        println!("✗ Key exchange failed: {}", e);
                        msg_tx.send(Message::System("Key exchange failed".into())).ok();
                        return;
                    }
                };

                println!("\n[STEP 4] Initializing session as initiator");
                println!("─────────────────────────────────────────────────────────");
                let (session, init_message) = match Session::new_initiator(&alice, &mut bob) {
                    Ok(s) => {
                        println!("✓ Session initialized with Double Ratchet");
                        s
                    }
                    Err(e) => {
                        println!("✗ Session initialization failed: {}", e);
                        msg_tx.send(Message::System("Session initialization failed".into())).ok();
                        return;
                    }
                };

                println!("\n[STEP 5] Sending initialization message");
                println!("─────────────────────────────────────────────────────────");
                let init_data = network::serialize_pqxdh_init_message(&init_message);
                print_hex_dump("Init Message", &init_data, 64);
                if network::send_message(&mut stream, &init_data).is_err() {
                    println!("✗ Failed to send init message");
                    return;
                }
                println!("✓ Init message transmitted");

                println!("\n╔════════════════════════════════════════════════════════╗");
                println!("║              SESSION ESTABLISHED (LISTENER)            ║");
                println!("╚════════════════════════════════════════════════════════╝");
                println!("Protocol: PQXDH with Double Ratchet");
                println!("KEM: ML-KEM-1024 (Kyber)");
                println!("DH: X25519");
                println!("Ready for encrypted messaging\n");
                msg_tx.send(Message::System("🔒 End-to-end encrypted".into())).ok();

                handle_chat(session, stream, rx, msg_tx, running);
            }
        });
    }

    fn start_connect(&mut self) {
        let address = self.connect_address.clone();
        
        println!("\n[CONNECTOR] Attempting to connect to {}", address);
        
        self.state = ConnectionState::Connecting;
        self.messages
            .push(Message::System(format!("Connecting to {}", address)));

        let (tx, rx) = mpsc::channel();
        let (msg_tx, msg_rx) = mpsc::channel();
        self.message_sender = Some(tx);
        *self.message_receiver.lock().unwrap() = Some(msg_rx);

        let running = Arc::clone(&self.running);
        let crypto_mode = self.crypto_mode;

        thread::spawn(move || {
            let mut stream = match TcpStream::connect(&address) {
                Ok(s) => {
                    println!("[CONNECTOR] ✓ TCP connection established");
                    msg_tx.send(Message::System("Connected! Establishing secure session...".into())).ok();
                    s
                }
                Err(e) => {
                    println!("[ERROR] Connection failed: {}", e);
                    msg_tx.send(Message::System(format!("Connection failed: {}", e)).into()).ok();
                    return;
                }
            };

            if crypto_mode == CryptoMode::KyberDilithiumAES {
                println!("\n╔════════════════════════════════════════════════════════╗");
                println!("║         KYBER-DILITHIUM-AES HANDSHAKE (CONNECTOR)     ║");
                println!("╚════════════════════════════════════════════════════════╝");
                msg_tx.send(Message::System("🔐 Using Kyber768 + Dilithium3 + AES-GCM".into())).ok();

                println!("\n[STEP 1] Generating Kyber keypair and Dilithium signing keys");
                println!("─────────────────────────────────────────────────────────");
                let my_data = Python::with_gil(|py| {
                    pineapple::kyber_dilithium::kd_init_handshake(py).expect("KD init")
                });
                println!("✓ Key generation complete");
                print_hex_dump("Kyber Public Key", &my_data.kyber_pk, 64);
                print_hex_dump("Kyber Secret Key", &my_data.kyber_sk, 64);
                print_hex_dump("Dilithium Public Key", &my_data.dilithium_pk, 64);
                print_hex_dump("Dilithium Secret Key", &my_data.dilithium_sk, 64);

                println!("\n[STEP 2] Receiving peer's public keys");
                println!("─────────────────────────────────────────────────────────");
                let theirs: pineapple::kyber_dilithium::KDHandshakeData =
                    pineapple::network_kd::recv_json(&mut stream).expect("KD recv peer");
                println!("✓ Peer keys received");
                print_hex_dump("Peer Kyber Public Key", &theirs.kyber_pk, 64);
                print_hex_dump("Peer Dilithium Public Key", &theirs.dilithium_pk, 64);

                println!("\n[STEP 3] Sending our public keys");
                println!("─────────────────────────────────────────────────────────");
                pineapple::network_kd::send_json(&mut stream, &my_data).expect("KD send");
                println!("✓ Public keys transmitted");

                println!("\n[STEP 4] Receiving Kyber ciphertext");
                println!("─────────────────────────────────────────────────────────");
                let ciphertext: Vec<u8> =
                    pineapple::network_kd::recv_json(&mut stream).expect("KD recv ciphertext");
                println!("✓ Ciphertext received");
                print_hex_dump("Kyber Ciphertext", &ciphertext, 64);

                println!("\n[STEP 5] Decapsulating shared secret");
                println!("─────────────────────────────────────────────────────────");
                let kd_session = Python::with_gil(|py| {
                    let shared = pineapple::kyber_dilithium::kd_finish_handshake(
                        py,
                        ciphertext,
                        my_data.kyber_sk.clone(),
                    )
                    .expect("KD finish");

                    println!("✓ Kyber decapsulation complete");
                    print_hex_dump("Shared Secret", &shared, 64);
                    println!("  Shared secret strength: {} bits", shared.len() * 8);

                    let session = pineapple::kyber_dilithium::KDSession::new(&shared);
                    println!("✓ AES-GCM session initialized with shared secret");
                    session
                });

                println!("\n╔════════════════════════════════════════════════════════╗");
                println!("║              SESSION ESTABLISHED (CONNECTOR)           ║");
                println!("╚════════════════════════════════════════════════════════╝");
                println!("Encryption: AES-256-GCM");
                println!("Key Exchange: Kyber768 (ML-KEM)");
                println!("Authentication: Dilithium3 (ML-DSA)");
                println!("Ready for encrypted messaging\n");
                msg_tx.send(Message::System("🔒 Encrypted using AES-GCM".into())).ok();
                
                handle_chat_kd(kd_session, stream, rx, msg_tx, running);
                return;
            }

            // PQXDH path
            println!("\n╔════════════════════════════════════════════════════════╗");
            println!("║              PQXDH HANDSHAKE (CONNECTOR)               ║");
            println!("╚════════════════════════════════════════════════════════╝");

            println!("\n[STEP 1] Generating PQXDH keys");
            println!("─────────────────────────────────────────────────────────");
            let mut bob = pqxdh::User::new();
            println!("✓ Keys generated (ML-KEM-1024 + X25519)");

            println!("\n[STEP 2] Receiving peer's public keys");
            println!("─────────────────────────────────────────────────────────");
            let _alice = match receive_public_keys(&mut stream) {
                Ok(a) => {
                    println!("✓ Peer keys received");
                    a
                }
                Err(e) => {
                    println!("✗ Key exchange failed: {}", e);
                    msg_tx.send(Message::System("Key exchange failed".into())).ok();
                    return;
                }
            };

            println!("\n[STEP 3] Sending our public keys");
            println!("─────────────────────────────────────────────────────────");
            if let Err(e) = send_public_keys(&mut stream, &bob) {
                println!("✗ Failed to send keys: {}", e);
                return;
            }
            println!("✓ Public keys transmitted");

            println!("\n[STEP 4] Receiving initialization message");
            println!("─────────────────────────────────────────────────────────");
            let init_message_data = match network::receive_message(&mut stream) {
                Ok(d) => {
                    print_hex_dump("Init Message", &d, 64);
                    println!("✓ Init message received");
                    d
                }
                Err(e) => {
                    println!("✗ Failed to receive init message: {}", e);
                    return;
                }
            };

            let init_message = match network::deserialize_pqxdh_init_message(&init_message_data) {
                Ok(m) => m,
                Err(e) => {
                    println!("✗ Failed to deserialize init message: {}", e);
                    return;
                }
            };

            println!("\n[STEP 5] Creating session as responder");
            println!("─────────────────────────────────────────────────────────");
            let session = match Session::new_responder(&mut bob, &init_message) {
                Ok(s) => {
                    println!("✓ Session created with Double Ratchet");
                    s
                }
                Err(e) => {
                    println!("✗ Session creation failed: {}", e);
                    return;
                }
            };

            println!("\n╔════════════════════════════════════════════════════════╗");
            println!("║              SESSION ESTABLISHED (CONNECTOR)           ║");
            println!("╚════════════════════════════════════════════════════════╝");
            println!("Protocol: PQXDH with Double Ratchet");
            println!("KEM: ML-KEM-1024 (Kyber)");
            println!("DH: X25519");
            println!("Ready for encrypted messaging\n");
            msg_tx.send(Message::System("🔒 End-to-end encrypted".into())).ok();

            handle_chat(session, stream, rx, msg_tx, running);
        });
    }

    fn send_message(&mut self) {
        if let Some(sender) = &self.message_sender {
            if !self.input_text.trim().is_empty() {
                let msg = self.input_text.clone();
                self.messages.push(Message::Text { 
                    content: msg.clone(), 
                    is_sent: true,
                    timestamp: SystemTime::now()
                });
                sender.send(msg).ok();
                self.input_text.clear();
            }
        }
    }

    fn disconnect(&mut self) {
        println!("\n[SESSION] Disconnecting...");
        self.running.store(false, Ordering::SeqCst);
        self.state = ConnectionState::Disconnected;
        self.messages.clear();
        self.message_sender = None;
        *self.message_receiver.lock().unwrap() = None;
        self.running = Arc::new(AtomicBool::new(true));
        println!("[SESSION] Disconnected\n");
    }
    
    fn format_time(time: SystemTime) -> String {
        match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => {
                let secs = duration.as_secs();
                let hours = (secs / 3600) % 24;
                let minutes = (secs / 60) % 60;
                format!("{:02}:{:02}", hours, minutes)
            }
            Err(_) => String::from("--:--"),
        }
    }
}

impl eframe::App for PineappleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll for incoming messages
        if let Some(receiver) = self.message_receiver.lock().unwrap().as_ref() {
            while let Ok(msg) = receiver.try_recv() {
                match msg {
                    Message::Text { content, is_sent: _, timestamp } => {
                        self.messages.push(Message::Text { 
                            content, 
                            is_sent: false,
                            timestamp 
                        });
                    }
                    Message::System(text) => {
                        if text.contains("End-to-end encrypted") || text.contains("Encrypted using AES-GCM") {
                            self.state = ConnectionState::Connected;
                        }
                        self.messages.push(Message::System(text));
                    }
                }
            }
        }

        // Handle copied notification timer
        if self.show_copied {
            self.copied_timer += ctx.input(|i| i.stable_dt);
            if self.copied_timer > 2.0 {
                self.show_copied = false;
                self.copied_timer = 0.0;
            }
        }

        ctx.request_repaint();

        match &self.state {
            ConnectionState::Disconnected => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let painter = ui.painter();
                    let rect = ui.available_rect_before_wrap();
                    painter.rect_filled(
                        rect,
                        0.0,
                        egui::Color32::from_rgb(17, 27, 33),
                    );

                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        
                        ui.horizontal(|ui| {
                            ui.add_space(ui.available_width() / 2.0 - 180.0);
                            ui.label(egui::RichText::new("🍍").size(60.0));
                            ui.label(egui::RichText::new("pineapple")
                                .size(56.0)
                                .color(egui::Color32::from_rgb(37, 211, 102))
                                .strong());
                        });
                        
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("Quantum-safe end-to-end encrypted messaging")
                            .size(16.0)
                            .color(egui::Color32::from_rgb(180, 180, 180)));
                        
                        ui.add_space(50.0);
                        
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(32, 44, 51))
                            .rounding(10.0)
                            .inner_margin(30.0)
                            .show(ui, |ui| {
                                ui.set_max_width(500.0);
                                ui.label(egui::RichText::new("Cryptography Mode").size(16.0));

                                ui.horizontal(|ui| {
                                    ui.selectable_value(&mut self.crypto_mode, CryptoMode::PQXDH, "PQXDH (default)");
                                    ui.selectable_value(&mut self.crypto_mode, CryptoMode::KyberDilithiumAES, "Kyber + Dilithium + AES");
                                });
                                ui.add_space(20.0);

                                let listen_btn = egui::Button::new(
                                    egui::RichText::new("📱  Start Listening")
                                        .size(18.0)
                                        .color(egui::Color32::WHITE)
                                )
                                .fill(egui::Color32::from_rgb(0, 168, 132))
                                .min_size(egui::vec2(460.0, 50.0))
                                .rounding(8.0);
                                
                                if ui.add(listen_btn).clicked() {
                                    self.start_listener();
                                }
                                
                                ui.add_space(20.0);
                                
                                ui.label(egui::RichText::new("OR")
                                    .size(14.0)
                                    .color(egui::Color32::GRAY));
                                
                                ui.add_space(20.0);
                                
                                ui.label(egui::RichText::new("Connect to peer")
                                    .size(16.0)
                                    .color(egui::Color32::from_rgb(200, 200, 200)));
                                
                                ui.add_space(10.0);
                                
                                let text_edit = egui::TextEdit::singleline(&mut self.connect_address)
                                    .hint_text("Enter address (e.g., 192.168.1.100:5000)")
                                    .font(egui::TextStyle::Body)
                                    .desired_width(460.0);
                                
                                let response = ui.add(text_edit);
                                
                                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                    if !self.connect_address.is_empty() {
                                        self.start_connect();
                                    }
                                }
                                
                                ui.add_space(10.0);
                                
                                let connect_btn = egui::Button::new(
                                    egui::RichText::new("Connect")
                                        .size(16.0)
                                )
                                .fill(egui::Color32::from_rgb(0, 168, 132))
                                .min_size(egui::vec2(460.0, 45.0))
                                .rounding(8.0);
                                
                                if ui.add(connect_btn).clicked() && !self.connect_address.is_empty() {
                                    self.start_connect();
                                }
                            });
                        
                        ui.add_space(30.0);
                        
                        ui.label(egui::RichText::new("Protected by ML-KEM-1024 (Kyber) · X25519 · PQXDH")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(120, 120, 120)));
                    });
                });
            }
            _ => {
                egui::TopBottomPanel::top("header")
                    .exact_height(60.0)
                    .show(ctx, |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add_space(10.0);
                            
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(40.0, 40.0),
                                egui::Sense::hover()
                            );
                            ui.painter().circle_filled(
                                rect.center(),
                                20.0,
                                egui::Color32::from_rgb(0, 168, 132),
                            );
                            ui.painter().text(
                                rect.center(),
                                egui::Align2::CENTER_CENTER,
                                "🔒",
                                egui::FontId::proportional(20.0),
                                egui::Color32::WHITE,
                            );
                            
                            ui.add_space(10.0);
                            
                            ui.vertical(|ui| {
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("Secure Chat")
                                    .size(16.0)
                                    .strong()
                                    .color(egui::Color32::WHITE));
                                
                                let status = match &self.state {
                                    ConnectionState::Listening(_) => "waiting for peer...",
                                    ConnectionState::Connecting => "connecting...",
                                    ConnectionState::Connected => "online",
                                    _ => "",
                                };
                                
                                ui.label(egui::RichText::new(status)
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(150, 150, 150)));
                            });
                            
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.add_space(10.0);
                                
                                let disconnect_btn = egui::Button::new(
                                    egui::RichText::new("✕")
                                        .size(20.0)
                                        .color(egui::Color32::from_rgb(200, 200, 200))
                                )
                                .fill(egui::Color32::TRANSPARENT)
                                .frame(false);
                                
                                if ui.add(disconnect_btn).clicked() {
                                    self.disconnect();
                                }
                            });
                        });
                    });

                if let ConnectionState::Listening(conn_str) = &self.state {
                    egui::TopBottomPanel::top("connection_banner")
                        .exact_height(50.0)
                        .show(ctx, |ui| {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(0, 95, 78))
                                .show(ui, |ui| {
                                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                        ui.add_space(15.0);
                                        ui.label(egui::RichText::new("Share this address:")
                                            .size(13.0)
                                            .color(egui::Color32::from_rgb(200, 200, 200)));
                                        
                                        ui.add_space(5.0);
                                        
                                        ui.label(egui::RichText::new(conn_str)
                                            .size(14.0)
                                            .color(egui::Color32::WHITE)
                                            .strong());
                                        
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            ui.add_space(15.0);
                                            
                                            let copy_text = if self.show_copied { "✓ Copied" } else { "📋 Copy" };
                                            let copy_btn = egui::Button::new(
                                                egui::RichText::new(copy_text).size(13.0)
                                            )
                                            .fill(egui::Color32::from_rgb(0, 168, 132))
                                            .rounding(5.0);
                                            
                                            if ui.add(copy_btn).clicked() {
                                                ui.output_mut(|o| o.copied_text = conn_str.clone());
                                                self.show_copied = true;
                                                self.copied_timer = 0.0;
                                            }
                                        });
                                    });
                                });
                        });
                }

                egui::TopBottomPanel::bottom("input")
                    .exact_height(60.0)
                    .show(ctx, |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add_space(10.0);
                            
                            let text_edit = egui::TextEdit::singleline(&mut self.input_text)
                                .hint_text("Type a message")
                                .font(egui::TextStyle::Body)
                                .frame(true)
                                .desired_width(ui.available_width() - 70.0);
                            
                            let response = ui.add(text_edit);
                            
                            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.send_message();
                                response.request_focus();
                            }
                            
                            ui.add_space(5.0);
                            
                            let send_btn = egui::Button::new(
                                egui::RichText::new("➤")
                                    .size(18.0)
                                    .color(egui::Color32::WHITE)
                            )
                            .fill(egui::Color32::from_rgb(0, 168, 132))
                            .min_size(egui::vec2(45.0, 45.0))
                            .rounding(22.5);
                            
                            if ui.add(send_btn).clicked() {
                                self.send_message();
                            }
                            
                            ui.add_space(10.0);
                        });
                    });

                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            ui.add_space(10.0);
                            
                            for msg in &self.messages {
                                match msg {
                                    Message::Text { content, is_sent, timestamp } => {
                                        if *is_sent {
                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                                ui.add_space(10.0);
                                                
                                                egui::Frame::none()
                                                    .fill(egui::Color32::from_rgb(5, 97, 78))
                                                    .rounding(8.0)
                                                    .inner_margin(egui::vec2(12.0, 8.0))
                                                    .show(ui, |ui| {
                                                        ui.set_max_width(500.0);
                                                        ui.vertical(|ui| {
                                                            ui.label(egui::RichText::new(content)
                                                                .size(15.0)
                                                                .color(egui::Color32::WHITE));
                                                            
                                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                                                ui.label(egui::RichText::new(Self::format_time(*timestamp))
                                                                    .size(11.0)
                                                                    .color(egui::Color32::from_rgb(180, 180, 180)));
                                                            });
                                                        });
                                                    });
                                            });
                                        } else {
                                            ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                                                ui.add_space(10.0);
                                                
                                                egui::Frame::none()
                                                    .fill(egui::Color32::from_rgb(32, 44, 51))
                                                    .rounding(8.0)
                                                    .inner_margin(egui::vec2(12.0, 8.0))
                                                    .show(ui, |ui| {
                                                        ui.set_max_width(500.0);
                                                        ui.vertical(|ui| {
                                                            ui.label(egui::RichText::new(content)
                                                                .size(15.0)
                                                                .color(egui::Color32::WHITE));
                                                            
                                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                                                ui.label(egui::RichText::new(Self::format_time(*timestamp))
                                                                    .size(11.0)
                                                                    .color(egui::Color32::from_rgb(150, 150, 150)));
                                                            });
                                                        });
                                                    });
                                            });
                                        }
                                        ui.add_space(6.0);
                                    }
                                    Message::System(text) => {
                                        ui.add_space(5.0);
                                        ui.vertical_centered(|ui| {
                                            egui::Frame::none()
                                                .fill(egui::Color32::from_rgb(42, 57, 66))
                                                .rounding(8.0)
                                                .inner_margin(egui::vec2(12.0, 6.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new(text)
                                                        .size(13.0)
                                                        .color(egui::Color32::from_rgb(180, 180, 180)));
                                                });
                                        });
                                        ui.add_space(5.0);
                                    }
                                }
                            }
                            
                            ui.add_space(10.0);
                        });
                });
            }
        }
    }
}

fn handle_chat_kd(
    session: pineapple::kyber_dilithium::KDSession,
    mut stream: TcpStream,
    outgoing_rx: Receiver<String>,
    incoming_tx: Sender<Message>,
    running: Arc<AtomicBool>,
) {
    let stream_clone = stream.try_clone().unwrap();
    let session = Arc::new(session);
    let session_clone = Arc::clone(&session);
    let running_clone = Arc::clone(&running);

    // Receiving thread
    thread::spawn(move || {
        let mut stream = stream_clone;
        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║              RECV THREAD STARTED (KD-AES)              ║");
        println!("╚════════════════════════════════════════════════════════╝\n");
        
        loop {
            if !running_clone.load(Ordering::SeqCst) {
                println!("\n[RECV] Thread stopping...");
                break;
            }
            
            match pineapple::network_kd::recv_json::<Vec<u8>>(&mut stream) {
                Ok(raw) if !raw.is_empty() => {
                    println!("\n┌─ INCOMING ENCRYPTED MESSAGE ────────────────────────");
                    print_hex_dump("│ Received Ciphertext", &raw, 128);
                    println!("│ Encryption: AES-256-GCM");
                    println!("│ Authentication: GCM tag included");
                    println!("├─ DECRYPTION ─────────────────────────────────────────");
                    
                    if let Ok(pt) = session_clone.decrypt(&raw) {
                        println!("│ ✓ Decryption successful");
                        println!("│ ✓ Authentication verified");
                        print_hex_dump("│ Plaintext (hex)", &pt, 128);
                        
                        if let Ok(msg) = String::from_utf8(pt.clone()) {
                            println!("│ Plaintext (UTF-8): \"{}\"", msg);
                            println!("└──────────────────────────────────────────────────────\n");
                            incoming_tx.send(Message::Text {
                                content: msg,
                                is_sent: false,
                                timestamp: SystemTime::now()
                            }).ok();
                        } else {
                            println!("│ ✗ UTF-8 decode failed");
                            println!("└──────────────────────────────────────────────────────\n");
                        }
                    } else {
                        println!("│ ✗ DECRYPTION FAILED");
                        println!("│ Possible causes: wrong key, tampered data, or replay");
                        println!("└──────────────────────────────────────────────────────\n");
                    }
                }
                Ok(_) => {
                    println!("[RECV] Received empty message");
                }
                Err(e) => {
                    println!("[RECV] ✗ Network error: {}", e);
                    break;
                }
            }
        }
        
        println!("[RECV] Thread terminated\n");
    });

    // Sending thread
    thread::spawn(move || {
        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║              SEND THREAD STARTED (KD-AES)              ║");
        println!("╚════════════════════════════════════════════════════════╝\n");
        
        while running.load(Ordering::SeqCst) {
            if let Ok(text) = outgoing_rx.recv() {
                if !text.is_empty() {
                    println!("\n┌─ OUTGOING MESSAGE ───────────────────────────────────");
                    println!("│ Original message: \"{}\"", text);
                    let plaintext_bytes = text.as_bytes();
                    print_hex_dump("│ Plaintext (hex)", plaintext_bytes, 128);
                    println!("├─ ENCRYPTION ─────────────────────────────────────────");
                    println!("│ Algorithm: AES-256-GCM");
                    println!("│ Key size: 256 bits");
                    println!("│ Generating random nonce...");
                    
                    if let Ok(ct) = session.encrypt(plaintext_bytes) {
                        println!("│ ✓ Encryption successful");
                        println!("│ ✓ Authentication tag generated");
                        print_hex_dump("│ Ciphertext", &ct, 128);
                        println!("├─ TRANSMISSION ───────────────────────────────────────");
                        
                        match pineapple::network_kd::send_json(&mut stream, &ct) {
                            Ok(_) => {
                                println!("│ ✓ Transmitted successfully");
                                println!("└──────────────────────────────────────────────────────\n");
                            }
                            Err(e) => {
                                println!("│ ✗ Transmission FAILED: {}", e);
                                println!("└──────────────────────────────────────────────────────\n");
                            }
                        }
                    } else {
                        println!("│ ✗ ENCRYPTION FAILED");
                        println!("└──────────────────────────────────────────────────────\n");
                    }
                }
            }
        }
        
        println!("[SEND] Thread terminated\n");
    });
}

fn send_public_keys(stream: &mut TcpStream, user: &pqxdh::User) -> anyhow::Result<()> {
    let bundle = network::serialize_prekey_bundle(user);
    print_hex_dump("Public Key Bundle", &bundle, 128);
    network::send_message(stream, &bundle)?;
    Ok(())
}

fn receive_public_keys(stream: &mut TcpStream) -> anyhow::Result<pqxdh::User> {
    let bundle_data = network::receive_message(stream)?;
    print_hex_dump("Received Key Bundle", &bundle_data, 128);
    let user = network::deserialize_prekey_bundle(&bundle_data)?;
    Ok(user)
}

fn handle_chat(
    session: Session,
    mut stream: TcpStream,
    outgoing_rx: Receiver<String>,
    incoming_tx: Sender<Message>,
    running: Arc<AtomicBool>,
) {
    let stream_clone = stream.try_clone().unwrap();
    let session = Arc::new(Mutex::new(session));
    let session_clone = Arc::clone(&session);
    let running_clone = Arc::clone(&running);

    // Receiving thread
    thread::spawn(move || {
        let mut stream = stream_clone;
        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║              RECV THREAD STARTED (PQXDH)               ║");
        println!("╚════════════════════════════════════════════════════════╝\n");
        
        loop {
            if !running_clone.load(Ordering::SeqCst) {
                println!("\n[RECV] Thread stopping...");
                break;
            }

            match network::receive_message(&mut stream) {
                Ok(msg_data) => {
                    println!("\n┌─ INCOMING DOUBLE RATCHET MESSAGE ───────────────────");
                    print_hex_dump("│ Ratchet Message", &msg_data, 128);
                    println!("├─ DESERIALIZATION ────────────────────────────────────");
                    
                    match network::deserialize_ratchet_message(&msg_data) {
                        Ok(msg) => {
                            println!("│ ✓ Message structure validated");
                            println!("│ Contains: header + encrypted body");
                            println!("├─ DOUBLE RATCHET DECRYPTION ──────────────────────────");
                            
                            let mut sess = session_clone.lock().unwrap();
                            match sess.receive(msg) {
                                Ok(plaintext_bytes) => {
                                    println!("│ ✓ Ratchet step successful");
                                    println!("│ ✓ Message keys derived");
                                    println!("│ ✓ Decryption successful");
                                    print_hex_dump("│ Plaintext (hex)", &plaintext_bytes, 128);
                                    println!("├─ MESSAGE PARSING ────────────────────────────────────");
                                    
                                    match messages::deserialize_message(&plaintext_bytes) {
                                        Ok(messages::MessageType::Text(text)) => {
                                            println!("│ Message type: Text");
                                            println!("│ Content: \"{}\"", text);
                                            println!("└──────────────────────────────────────────────────────\n");
                                            incoming_tx.send(Message::Text {
                                                content: text,
                                                is_sent: false,
                                                timestamp: SystemTime::now()
                                            }).ok();
                                        }
                                        Ok(messages::MessageType::File { filename, data }) => {
                                            println!("│ Message type: File");
                                            println!("│ Filename: {}", filename);
                                            println!("│ Size: {} bytes", data.len());
                                            let save_path = format!("received_{}", filename);
                                            if std::fs::write(&save_path, data).is_ok() {
                                                println!("│ ✓ Saved to: {}", save_path);
                                                println!("└──────────────────────────────────────────────────────\n");
                                                incoming_tx.send(Message::System(
                                                    format!("📎 Received file: {}", filename)
                                                )).ok();
                                            }
                                        }
                                        Err(e) => {
                                            println!("│ ✗ Message parsing failed: {:?}", e);
                                            println!("└──────────────────────────────────────────────────────\n");
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("│ ✗ RATCHET DECRYPTION FAILED: {:?}", e);
                                    println!("│ Possible causes: out-of-order, wrong session");
                                    println!("└──────────────────────────────────────────────────────\n");
                                }
                            }
                        }
                        Err(e) => {
                            println!("│ ✗ Deserialization failed: {:?}", e);
                            println!("└──────────────────────────────────────────────────────\n");
                        }
                    }
                }
                Err(e) => {
                    println!("[RECV] ✗ Network error: {:?}", e);
                    break;
                }
            }
        }
        
        println!("[RECV] Thread terminated\n");
    });

    // Sending thread
    thread::spawn(move || {
        println!("\n╔════════════════════════════════════════════════════════╗");
        println!("║              SEND THREAD STARTED (PQXDH)               ║");
        println!("╚════════════════════════════════════════════════════════╝\n");
        
        while running.load(Ordering::SeqCst) {
            if let Ok(text) = outgoing_rx.recv() {
                println!("\n┌─ OUTGOING MESSAGE ───────────────────────────────────");
                println!("│ Original message: \"{}\"", text);
                
                let msg_bytes = messages::serialize_message(&messages::MessageType::Text(text));
                print_hex_dump("│ Serialized message", &msg_bytes, 128);
                println!("├─ DOUBLE RATCHET ENCRYPTION ──────────────────────────");
                println!("│ Performing ratchet step...");
                println!("│ Deriving message keys...");
                
                let mut sess = session.lock().unwrap();
                
                if let Ok(msg) = sess.send_bytes(&msg_bytes) {
                    println!("│ ✓ Ratchet step complete");
                    println!("│ ✓ Message encrypted");
                    drop(sess);
                    
                    let msg_data = network::serialize_ratchet_message(&msg);
                    print_hex_dump("│ Ratchet Message", &msg_data, 128);
                    println!("├─ TRANSMISSION ───────────────────────────────────────");
                    
                    if network::send_message(&mut stream, &msg_data).is_err() {
                        println!("│ ✗ Transmission FAILED");
                        println!("└──────────────────────────────────────────────────────\n");
                        break;
                    }
                    println!("│ ✓ Transmitted successfully");
                    println!("└──────────────────────────────────────────────────────\n");
                } else {
                    println!("│ ✗ ENCRYPTION FAILED");
                    println!("└──────────────────────────────────────────────────────\n");
                }
            }
        }
        
        println!("[SEND] Thread terminated\n");
    });
}