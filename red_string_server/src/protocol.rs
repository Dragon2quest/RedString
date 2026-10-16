use serde::{Deserialize, Serialize};

pub const FRAME_TYPE_TEXT: u8 = 0x01;
pub const FRAME_TYPE_BINARY: u8 = 0x02;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ControlPacket {
    #[serde(rename = "HANDSHAKE_INIT")]
    HandshakeInit {
        device_name: String,
        platform_soft_limit_bytes: u64,
        platform_flex_limit_bytes: u64,
    },
    #[serde(rename = "FATE_SYNC_TEXT")]
    FateSyncText {
        sender: String,
        content: String,
    },
    #[serde(rename = "FATE_WATCH_DELTA")]
    FateWatchDelta {
        action: String, // "insert" or "delete"
        chars: String,
    },
    #[serde(rename = "FILE_OFFER")]
    FileOffer {
        file_name: String,
        total_size: u64,
    },
}

pub struct PlatformBuffer {
    pub soft_limit: u64,
    pub flex_limit: u64,
    pub current_usage: u64,
}

impl PlatformBuffer {
    pub fn new(soft_mb: u64) -> Self {
        let soft_limit = soft_mb * 1024 * 1024;
        let flex_limit = soft_limit + (soft_limit * 15 / 100); // +15% elastic margin
        Self {
            soft_limit,
            flex_limit,
            current_usage: 0,
        }
    }

    pub fn can_accept(&self, file_size: u64) -> Result<bool, &'static str> {
        let projected = self.current_usage + file_size;
        if projected > self.flex_limit {
            Err("Platform hard ceiling exceeded. File rejected.")
        } else if projected > self.soft_limit {
            Ok(true) // Accepted into elastic flex zone
        } else {
            Ok(false) // Standard transfer
        }
    }
}
