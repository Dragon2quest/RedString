pub mod protocol;

use byteorder::{BigEndian, ByteOrder};
use local_ip_address::local_ip;
use protocol::{ControlPacket, PlatformBuffer, FRAME_TYPE_BINARY, FRAME_TYPE_TEXT};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[tauri::command]
fn get_local_ip() -> String {
    local_ip().unwrap_or([127, 0, 0, 1].into()).to_string()
}

#[tauri::command]
async fn connect_to_peer(ip: String) -> Result<String, String> {
    let addr = if ip.contains(':') {
        ip.clone()
    } else {
        format!("{}:7788", ip)
    };

    println!("[*] Attempting outbound weave to {}...", addr);
    
    match TcpStream::connect(&addr).await {
        Ok(socket) => {
            println!("[+] Outbound thread established with: {}", addr);
            let platform = Arc::new(Mutex::new(PlatformBuffer::new(1024)));
            let peer_addr_str = addr.clone();
            
            // Spawn the handler task in the background
            tokio::spawn(async move {
                handle_connection(socket, platform, peer_addr_str).await;
            });
            
            Ok(format!("Connected to {}", addr))
        }
        Err(e) => {
            let err_msg = format!("Failed to weave thread with {}: {}", addr, e);
            eprintln!("[-] {}", err_msg);
            Err(err_msg)
        }
    }
}

pub fn run() {
    tauri::Builder::default()
        .setup(|_app| {
            // Start the Tokio TCP server in the background
            tauri::async_runtime::spawn(async move {
                start_tcp_server().await;
            });
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_local_ip, connect_to_peer])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn handle_connection(mut socket: TcpStream, platform: Arc<Mutex<PlatformBuffer>>, peer_addr: String) {
    let mut header_buf = [0u8; 5];
    let mut active_file: Option<File> = None;

    loop {
        // Read 5-byte frame header: [Type: 1B][Length: 4B]
        if socket.read_exact(&mut header_buf).await.is_err() {
            println!("[-] Thread severed with: {}", peer_addr);
            break;
        }

        let frame_type = header_buf[0];
        let payload_len = BigEndian::read_u32(&header_buf[1..5]) as usize;

        let mut payload = vec![0u8; payload_len];
        if socket.read_exact(&mut payload).await.is_err() {
            eprintln!("[!] Packet read failed from {}.", peer_addr);
            break;
        }

        match frame_type {
            FRAME_TYPE_TEXT => {
                if let Ok(pkt) = serde_json::from_slice::<ControlPacket>(&payload) {
                    match pkt {
                        ControlPacket::FateWatchDelta { action, chars } => {
                            if action == "insert" {
                                print!("{}", chars);
                                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                            } else if action == "delete" {
                                print!("\x08 \x08"); // Backspace visual
                                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                            }
                        }
                        ControlPacket::FateSyncText { sender, content } => {
                            println!("\n[Fate Sync - {}] {}: {}", peer_addr, sender, content);
                        }
                        ControlPacket::FileOffer { file_name, total_size } => {
                            let mut p = platform.lock().await;
                            match p.can_accept(total_size) {
                                Ok(in_flex) => {
                                    if in_flex {
                                        println!("\n[!] WARNING: File enters +15% Elastic Buffer Zone.");
                                    }
                                    println!("[Platform] Receiving incoming artifact from {}: {} ({} bytes)", peer_addr, file_name, total_size);
                                    if let Ok(file) = File::create(format!("received_{}", file_name)).await {
                                        active_file = Some(file);
                                        p.current_usage += total_size;
                                    } else {
                                        eprintln!("[!] Failed to create local file.");
                                    }
                                }
                                Err(reason) => {
                                    eprintln!("\n[Platform Drop Rejected from {}]: {}", peer_addr, reason);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            FRAME_TYPE_BINARY => {
                if let Some(ref mut file) = active_file {
                    if let Err(e) = file.write_all(&payload).await {
                        eprintln!("[!] Failed writing chunk to disk: {}", e);
                    }
                }
            }
            _ => eprintln!("[!] Unknown frame prefix: 0x{:02X}", frame_type),
        }
    }
}

async fn start_tcp_server() {
    let my_ip = local_ip().unwrap_or([127, 0, 0, 1].into());
    let port = 7788;
    let bind_addr = format!("0.0.0.0:{}", port);
    
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[!] Failed to bind TCP listener: {}", e);
            return;
        }
    };

    let platform = Arc::new(Mutex::new(PlatformBuffer::new(1024))); // Default: 1 GB Soft Limit

    println!("========================================================");
    println!("             RED STRING - THE CORE WEAVE               ");
    println!("========================================================");
    println!("[*] Desktop listening on: {}:{}", my_ip, port);

    loop {
        let (socket, peer_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(_) => continue,
        };
        println!("[+] Red String connection forged with peer: {}", peer_addr);
        let platform_ref = Arc::clone(&platform);
        let peer_addr_str = peer_addr.to_string();

        tokio::spawn(async move {
            handle_connection(socket, platform_ref, peer_addr_str).await;
        });
    }
}
