#[cfg(target_os = "linux")]
use std::{env, ffi::CString};

use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};

use crate::proxy::stages::ProfileStore;

#[cfg(target_os = "linux")]
const DEFAULT_PACKET_PROFILE_MAP_PATH: &str = "/sys/fs/bpf/404/fingerprint_profiles";
const INVALID_OPTION_OFFSET: u8 = 0xFF;

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BpfMapUpdateElemAttr {
    map_fd: u32,
    pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[cfg(target_os = "linux")]
const _: [(); 16] = [(); std::mem::size_of::<BpfObjGetAttr>()];
#[cfg(target_os = "linux")]
const _: [(); 0] = [(); std::mem::offset_of!(BpfObjGetAttr, pathname)];
#[cfg(target_os = "linux")]
const _: [(); 8] = [(); std::mem::offset_of!(BpfObjGetAttr, bpf_fd)];

#[cfg(target_os = "linux")]
const _: [(); 32] = [(); std::mem::size_of::<BpfMapUpdateElemAttr>()];
#[cfg(target_os = "linux")]
const _: [(); 8] = [(); std::mem::offset_of!(BpfMapUpdateElemAttr, key)];
#[cfg(target_os = "linux")]
const _: [(); 16] = [(); std::mem::offset_of!(BpfMapUpdateElemAttr, value)];
#[cfg(target_os = "linux")]
const _: [(); 24] = [(); std::mem::offset_of!(BpfMapUpdateElemAttr, flags)];

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct PacketProfile {
    pub ttl: u8,
    pub tos: u8,
    pub tcp_window: u16,
    pub tcp_mss: u16,
    pub tcp_window_scale: u8,
    pub randomize_tcp_timestamp: u8,
    pub randomize_ipv4_id: u8,
    pub randomize_ipv6_flow: u8,
    pub options_len: u8,
    pub mss_value_offset: u8,
    pub tsval_value_offset: u8,
    pub window_scale_value_offset: u8,
    pub reserved: [u8; 4],
    pub options: [u8; 40],
}

impl PacketProfile {
    pub fn from_profile_config(config: &Value) -> Result<Self> {
        let profile_identity = config.get("profile_identity").and_then(Value::as_object);
        let fingerprint = config.get("fingerprint").and_then(Value::as_object);
        let platform = profile_platform(profile_identity, fingerprint);

        let mut profile = match platform.as_str() {
            "macos" => Self::macos_default(),
            "linux" | "android" => Self::linux_default(),
            _ => Self::windows_default(),
        };

        if let Some(packet_profile) = config.get("packet_profile").and_then(Value::as_object) {
            profile.apply_json_overrides(packet_profile)?;
        }

        Ok(profile)
    }

    fn windows_default() -> Self {
        Self::with_tokens(
            128,
            0x10,
            64240,
            1460,
            8,
            false,
            true,
            true,
            &["mss", "nop", "window_scale", "nop", "nop", "sack_permitted"],
        )
        .expect("valid built-in Windows packet profile")
    }

    fn macos_default() -> Self {
        Self::with_tokens(
            64,
            0x10,
            65535,
            1460,
            6,
            true,
            true,
            true,
            &["mss", "nop", "window_scale", "nop", "nop", "timestamp", "sack_permitted", "eol"],
        )
        .expect("valid built-in macOS packet profile")
    }

    fn linux_default() -> Self {
        Self::with_tokens(
            64,
            0x10,
            65535,
            1460,
            7,
            true,
            true,
            true,
            &["mss", "sack_permitted", "timestamp", "nop", "window_scale"],
        )
        .expect("valid built-in Linux packet profile")
    }

    fn with_tokens(
        ttl: u8,
        tos: u8,
        tcp_window: u16,
        tcp_mss: u16,
        tcp_window_scale: u8,
        randomize_tcp_timestamp: bool,
        randomize_ipv4_id: bool,
        randomize_ipv6_flow: bool,
        tokens: &[&str],
    ) -> Result<Self> {
        let layout = build_option_layout(tokens)?;
        Ok(Self {
            ttl,
            tos,
            tcp_window,
            tcp_mss,
            tcp_window_scale,
            randomize_tcp_timestamp: u8::from(randomize_tcp_timestamp && layout.tsval_value_offset != INVALID_OPTION_OFFSET),
            randomize_ipv4_id: u8::from(randomize_ipv4_id),
            randomize_ipv6_flow: u8::from(randomize_ipv6_flow),
            options_len: layout.options_len,
            mss_value_offset: layout.mss_value_offset,
            tsval_value_offset: layout.tsval_value_offset,
            window_scale_value_offset: layout.window_scale_value_offset,
            reserved: [0; 4],
            options: layout.options,
        })
    }

    fn apply_json_overrides(&mut self, packet_profile: &Map<String, Value>) -> Result<()> {
        let timestamp_randomization_requested = packet_profile.contains_key("randomize_tcp_timestamp");

        if let Some(value) = packet_profile.get("ttl") {
            self.ttl = parse_u8_field(value, "packet_profile.ttl")?;
        }
        if let Some(value) = packet_profile.get("tos") {
            self.tos = parse_u8_field(value, "packet_profile.tos")?;
        }
        if let Some(value) = packet_profile.get("tcp_window") {
            self.tcp_window = parse_u16_field(value, "packet_profile.tcp_window")?;
        }
        if let Some(value) = packet_profile.get("tcp_mss") {
            self.tcp_mss = parse_u16_field(value, "packet_profile.tcp_mss")?;
        }
        if let Some(value) = packet_profile.get("tcp_window_scale") {
            self.tcp_window_scale = parse_u8_field(value, "packet_profile.tcp_window_scale")?;
        }
        if let Some(value) = packet_profile.get("randomize_tcp_timestamp") {
            self.randomize_tcp_timestamp = u8::from(parse_bool_field(value, "packet_profile.randomize_tcp_timestamp")?);
        }
        if let Some(value) = packet_profile.get("randomize_ipv4_id") {
            self.randomize_ipv4_id = u8::from(parse_bool_field(value, "packet_profile.randomize_ipv4_id")?);
        }
        if let Some(value) = packet_profile.get("randomize_ipv6_flow") {
            self.randomize_ipv6_flow = u8::from(parse_bool_field(value, "packet_profile.randomize_ipv6_flow")?);
        }
        if let Some(value) = packet_profile.get("options") {
            let layout = build_option_layout_from_value(value)?;
            self.options_len = layout.options_len;
            self.mss_value_offset = layout.mss_value_offset;
            self.tsval_value_offset = layout.tsval_value_offset;
            self.window_scale_value_offset = layout.window_scale_value_offset;
            self.options = layout.options;
        }

        if self.tsval_value_offset == INVALID_OPTION_OFFSET {
            if timestamp_randomization_requested && self.randomize_tcp_timestamp != 0 {
                return Err(anyhow!(
                    "packet_profile.randomize_tcp_timestamp requires a timestamp option in packet_profile.options"
                ));
            }

            self.randomize_tcp_timestamp = 0;
        }

        Ok(())
    }
}

struct PacketOptionLayout {
    options_len: u8,
    mss_value_offset: u8,
    tsval_value_offset: u8,
    window_scale_value_offset: u8,
    options: [u8; 40],
}

pub fn sync_profile_store(store: &ProfileStore) {
    #[cfg(target_os = "linux")]
    {
        let Some(config) = store.active_profile_config() else {
            return;
        };

        let packet_profile = match PacketProfile::from_profile_config(&config) {
            Ok(profile) => profile,
            Err(error) => {
                tracing::warn!("failed to derive packet profile from the active runtime profile: {error:#}");
                return;
            }
        };

        if let Err(error) = write_pinned_packet_profile(&packet_profile) {
            tracing::warn!("failed to sync packet profile into pinned eBPF map: {error:#}");
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = store;
}

fn profile_platform(
    profile_identity: Option<&Map<String, Value>>,
    fingerprint: Option<&Map<String, Value>>,
) -> String {
    profile_identity
        .and_then(|identity| identity.get("platform"))
        .and_then(Value::as_str)
        .map(normalize_platform)
        .or_else(|| {
            fingerprint
                .and_then(|entry| entry.get("os"))
                .and_then(Value::as_str)
                .map(normalize_platform)
        })
        .unwrap_or_else(|| "windows".to_string())
}

fn normalize_platform(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "windows" | "win32" | "win64" => "windows".to_string(),
        "macos" | "mac os" | "mac" | "macintel" => "macos".to_string(),
        "linux" | "x11" => "linux".to_string(),
        "android" => "android".to_string(),
        other => other.to_string(),
    }
}

fn parse_u8_field(value: &Value, field: &str) -> Result<u8> {
    let raw = value
        .as_u64()
        .ok_or_else(|| anyhow!("{field} must be an unsigned integer"))?;
    u8::try_from(raw).with_context(|| format!("{field} must fit in u8"))
}

fn parse_u16_field(value: &Value, field: &str) -> Result<u16> {
    let raw = value
        .as_u64()
        .ok_or_else(|| anyhow!("{field} must be an unsigned integer"))?;
    u16::try_from(raw).with_context(|| format!("{field} must fit in u16"))
}

fn parse_bool_field(value: &Value, field: &str) -> Result<bool> {
    value
        .as_bool()
        .ok_or_else(|| anyhow!("{field} must be a boolean"))
}

fn build_option_layout_from_value(value: &Value) -> Result<PacketOptionLayout> {
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow!("packet_profile.options must be an array of symbolic option names"))?;

    let mut tokens = Vec::with_capacity(entries.len());
    for entry in entries {
        let token = entry
            .as_str()
            .ok_or_else(|| anyhow!("packet_profile.options entries must be strings"))?;
        tokens.push(token);
    }

    build_option_layout(&tokens)
}

fn build_option_layout(tokens: &[impl AsRef<str>]) -> Result<PacketOptionLayout> {
    let mut bytes = [0u8; 40];
    let mut cursor = 0usize;
    let mut mss_value_offset = INVALID_OPTION_OFFSET;
    let mut tsval_value_offset = INVALID_OPTION_OFFSET;
    let mut window_scale_value_offset = INVALID_OPTION_OFFSET;

    for token in tokens {
        let token = token.as_ref().trim().to_ascii_lowercase();
        let encoded: &[u8] = match token.as_str() {
            "mss" => {
                mss_value_offset = (cursor + 2) as u8;
                &[2, 4, 0, 0]
            }
            "nop" => &[1],
            "window_scale" | "ws" => {
                window_scale_value_offset = (cursor + 2) as u8;
                &[3, 3, 0]
            }
            "sack_permitted" | "sack" => &[4, 2],
            "timestamp" | "timestamps" | "ts" => {
                tsval_value_offset = (cursor + 2) as u8;
                &[8, 10, 0, 0, 0, 0, 0, 0, 0, 0]
            }
            "eol" => &[0],
            other => {
                return Err(anyhow!("unsupported packet_profile option token '{other}'"));
            }
        };

        if cursor + encoded.len() > bytes.len() {
            return Err(anyhow!("packet_profile.options exceeds the TCP 40-byte option budget"));
        }

        bytes[cursor..cursor + encoded.len()].copy_from_slice(encoded);
        cursor += encoded.len();
    }

    if cursor == 0 {
        return Err(anyhow!("packet_profile.options may not be empty"));
    }

    while cursor % 4 != 0 {
        if cursor >= bytes.len() {
            return Err(anyhow!("packet_profile.options padding exceeds the TCP 40-byte option budget"));
        }
        bytes[cursor] = 1;
        cursor += 1;
    }

    Ok(PacketOptionLayout {
        options_len: cursor as u8,
        mss_value_offset,
        tsval_value_offset,
        window_scale_value_offset,
        options: bytes,
    })
}

#[cfg(target_os = "linux")]
fn write_pinned_packet_profile(profile: &PacketProfile) -> Result<()> {
    let map_path = env::var("STATIC_EBPF_MAP_PATH")
        .unwrap_or_else(|_| DEFAULT_PACKET_PROFILE_MAP_PATH.to_string());
    let fd = open_pinned_bpf_object(&map_path)
        .with_context(|| format!("failed to open pinned eBPF map at {map_path}"))?;

    let key = 0u32;
    let result = update_bpf_map_elem(fd, &key, profile);
    unsafe {
        libc::close(fd);
    }
    result
}

#[cfg(target_os = "linux")]
fn open_pinned_bpf_object(path: &str) -> Result<i32> {
    const BPF_OBJ_GET: libc::c_uint = 7;

    let c_path = CString::new(path).context("eBPF map path contains an interior NUL byte")?;
    let attr = BpfObjGetAttr {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &attr,
            std::mem::size_of::<BpfObjGetAttr>(),
        )
    } as i32;

    if fd < 0 {
        Err(std::io::Error::last_os_error()).context("BPF_OBJ_GET failed")
    } else {
        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
fn update_bpf_map_elem(fd: i32, key: &u32, value: &PacketProfile) -> Result<()> {
    const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
    const BPF_ANY: u64 = 0;

    let attr = BpfMapUpdateElemAttr {
        map_fd: fd as u32,
        pad0: 0,
        key: key as *const u32 as u64,
        value: value as *const PacketProfile as u64,
        flags: BPF_ANY,
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapUpdateElemAttr>(),
        )
    } as i32;

    if result < 0 {
        Err(std::io::Error::last_os_error()).context("BPF_MAP_UPDATE_ELEM failed")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PacketProfile;

    #[test]
    fn derives_windows_packet_defaults_from_profile_identity() {
        let config = serde_json::json!({
            "profile_identity": {
                "family": "chromium-like",
                "variant": "chrome",
                "platform": "windows"
            },
            "fingerprint": {
                "name": "Chrome Windows"
            }
        });

        let packet_profile = PacketProfile::from_profile_config(&config).expect("derive packet profile");

        assert_eq!(packet_profile.ttl, 128);
        assert_eq!(packet_profile.tcp_window, 64240);
        assert_eq!(packet_profile.tcp_window_scale, 8);
        assert_eq!(packet_profile.randomize_tcp_timestamp, 0);
        assert_eq!(packet_profile.options_len, 12);
        assert_eq!(packet_profile.mss_value_offset, 2);
        assert_eq!(packet_profile.window_scale_value_offset, 7);
        assert_eq!(packet_profile.tsval_value_offset, 0xFF);
    }

    #[test]
    fn packet_profile_accepts_symbolic_option_overrides() {
        let config = serde_json::json!({
            "profile_identity": {
                "platform": "windows"
            },
            "packet_profile": {
                "ttl": 64,
                "tcp_window": 65535,
                "tcp_window_scale": 7,
                "randomize_tcp_timestamp": true,
                "options": ["mss", "sack_permitted", "timestamp", "nop", "window_scale"]
            }
        });

        let packet_profile = PacketProfile::from_profile_config(&config).expect("derive packet profile");

        assert_eq!(packet_profile.ttl, 64);
        assert_eq!(packet_profile.tcp_window, 65535);
        assert_eq!(packet_profile.tcp_window_scale, 7);
        assert_eq!(packet_profile.randomize_tcp_timestamp, 1);
        assert_eq!(packet_profile.options_len, 20);
        assert_eq!(packet_profile.tsval_value_offset, 8);
        assert_eq!(packet_profile.window_scale_value_offset, 19);
    }

    #[test]
    fn packet_profile_rejects_timestamp_randomization_without_timestamp_option() {
        let config = serde_json::json!({
            "profile_identity": {
                "platform": "windows"
            },
            "packet_profile": {
                "randomize_tcp_timestamp": true,
                "options": ["mss", "nop", "window_scale", "nop", "nop", "sack_permitted"]
            }
        });

        let error = PacketProfile::from_profile_config(&config).expect_err("reject invalid packet profile");

        assert!(
            error.to_string().contains("randomize_tcp_timestamp requires a timestamp option"),
            "unexpected error: {error:#}"
        );
    }
}