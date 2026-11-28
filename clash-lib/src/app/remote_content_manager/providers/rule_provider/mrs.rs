use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use ipnet::IpNet;
use std::{
    io::{BufReader, Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tracing::{debug, error, warn};

use crate::{
    app::remote_content_manager::providers::rule_provider::{
        RuleSetBehavior,
        cidr_trie::CidrTrie,
        provider::{RuleContent, RuleSet},
    },
    common::succinct_set::DomainSet,
};

// MRS Magic bytes for version 1
const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1]; // MRSv1

// MRS Payload Versions
const DOMAIN_SET_VERSION: u8 = 0x01;
const IP_CIDR_SET_VERSION: u8 = 0x01;

// Behavior byte values from spec
const BEHAVIOR_DOMAIN: u8 = 0x00;
const BEHAVIOR_IPCIDR: u8 = 0x01;

impl RuleSetBehavior {
    /// Convert behavior to byte representation used in MRS format
    pub fn to_mrs_byte(self) -> Option<u8> {
        match self {
            RuleSetBehavior::Domain => Some(BEHAVIOR_DOMAIN),
            RuleSetBehavior::Ipcidr => Some(BEHAVIOR_IPCIDR),
            RuleSetBehavior::Classical => None, // Classical is not supported by MRS
        }
    }

    /// Create behavior from MRS byte representation
    pub fn from_mrs_byte(b: u8) -> Result<Self> {
        match b {
            BEHAVIOR_DOMAIN => Ok(RuleSetBehavior::Domain),
            BEHAVIOR_IPCIDR => Ok(RuleSetBehavior::Ipcidr),
            _ => bail!("Invalid MRS behavior byte: {}", b),
        }
    }
}

/// Parses MRS format rule set according to the v1 specification.
pub fn rules_mrs_parse(
    buf: &[u8],
    expected_behavior: RuleSetBehavior,
) -> Result<RuleSet> {
    // 1. Decompress using Zstandard
    let cursor = Cursor::new(buf);
    let mut reader = BufReader::new(
        zstd::Decoder::new(cursor).context("Failed to create zstd decoder")?,
    );

    // --- Header Parsing ---
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("Failed to read MRS magic bytes")?;
    if magic != MRS_MAGIC_BYTES {
        bail!(
            "Invalid MRS magic bytes. Expected {:?} but got {:?}",
            MRS_MAGIC_BYTES,
            magic
        );
    }

    let behavior_byte = reader
        .read_u8()
        .context("Failed to read MRS behavior byte")?;
    let actual_behavior = RuleSetBehavior::from_mrs_byte(behavior_byte)?;

    if actual_behavior != expected_behavior {
        bail!(
            "MRS behavior mismatch: file contains {:?} but expected {:?}",
            actual_behavior,
            expected_behavior
        );
    }

    let count = reader
        .read_i64::<BigEndian>()
        .context("Failed to read MRS rule count")?;
    if count < 0 {
        bail!("Invalid MRS rule count: {}", count);
    }
    debug!("MRS rule count: {}", count);

    let extra_length = reader
        .read_i64::<BigEndian>()
        .context("Failed to read MRS extra length")?;
    if extra_length != 0 {
        bail!(
            "Invalid MRS extra length for v1: expected 0, got {}",
            extra_length
        );
    }

    // --- Payload Parsing ---
    let content = match actual_behavior {
        RuleSetBehavior::Domain => parse_domain_payload(&mut reader),
        RuleSetBehavior::Ipcidr => parse_ipcidr_payload(&mut reader),
        RuleSetBehavior::Classical => {
            bail!("Classical behavior is not supported by MRS format")
        }
    }?;
    Ok(RuleSet {
        content,
        rule_count: count as u64,
    })
}

// --- Domain Payload Parsing ---
fn parse_domain_payload<R: Read>(reader: &mut R) -> Result<RuleContent> {
    let version = reader
        .read_u8()
        .context("Failed to read DomainSet version")?;
    if version != DOMAIN_SET_VERSION {
        bail!(
            "Unsupported DomainSet version: expected {}, got {}",
            DOMAIN_SET_VERSION,
            version
        );
    }

    let leaves_len = read_u64_length(reader, "Leaves")?;
    let leaves = read_u64_vec(reader, leaves_len, "Leaves")?;

    let label_bitmap_len = read_u64_length(reader, "LabelBitmap")?;
    let label_bitmap = read_u64_vec(reader, label_bitmap_len, "LabelBitmap")?;

    let labels_len = read_u64_length(reader, "Labels")?;
    let labels = read_byte_vec(reader, labels_len, "Labels")?;

    let domain_set = DomainSet::from_mrs_parts(leaves, label_bitmap, labels);
    Ok(RuleContent::Domain(domain_set))
}

// --- IPCIDR Payload Parsing ---
fn parse_ipcidr_payload<R: Read>(reader: &mut R) -> Result<RuleContent> {
    let version = reader
        .read_u8()
        .context("Failed to read IpCidrSet version")?;
    if version != IP_CIDR_SET_VERSION {
        bail!(
            "Unsupported IpCidrSet version: expected {}, got {}",
            IP_CIDR_SET_VERSION,
            version
        );
    }

    let ranges_len = read_u64_length(reader, "Ranges")?;
    debug!("Expecting {} IP ranges", ranges_len);

    let mut cidr_trie = CidrTrie::new();

    for i in 0..ranges_len {
        let mut range_buf = [0u8; 32];
        reader
            .read_exact(&mut range_buf)
            .with_context(|| format!("Failed to read IP range #{i}"))?;

        let from_ip_bytes: [u8; 16] = range_buf[0..16].try_into().unwrap();
        let to_ip_bytes: [u8; 16] = range_buf[16..32].try_into().unwrap();
        let from_ip = IpAddr::from(from_ip_bytes);
        let to_ip = IpAddr::from(to_ip_bytes);

        // Convert the range to CIDRs
        match range_to_cidrs(from_ip, to_ip) {
            Ok(cidrs) => {
                for cidr in cidrs {
                    // CidrTrie::insert expects a &str
                    if !cidr_trie.insert(&cidr.to_string()) {
                        // Log potentially invalid CIDR strings if insert fails
                        warn!(
                            "Failed to insert CIDR {} derived from range {} - {} \
                             into CidrTrie",
                            cidr, from_ip, to_ip
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to convert range {} - {} to CIDRs for range #{}: {}",
                    from_ip, to_ip, i, e
                );
                // Decide whether to continue or bail out
                // continue; // Skip this range
                return Err(e).context(format!("Error processing IP range #{i}")); // Bail out
            }
        }
    }

    debug!(
        "Successfully parsed and inserted CIDRs from {} ranges.",
        ranges_len
    );
    Ok(RuleContent::Ipcidr(Box::new(cidr_trie)))
}

// --- Helper Functions for Reading Data ---
fn read_u64_length<R: Read>(reader: &mut R, field_name: &str) -> Result<usize> {
    let len = reader
        .read_i64::<BigEndian>()
        .with_context(|| format!("Failed to read MRS {field_name} length"))?;
    if len < 0 {
        bail!("Invalid negative length for {}: {}", field_name, len);
    }
    Ok(len as usize)
}

fn read_u64_vec<R: Read>(
    reader: &mut R,
    count: usize,
    field_name: &str,
) -> Result<Vec<u64>> {
    let mut vec = Vec::with_capacity(count);
    for i in 0..count {
        let val = reader.read_u64::<BigEndian>().with_context(|| {
            format!("Failed to read {field_name} data element #{i}")
        })?;
        vec.push(val);
    }
    Ok(vec)
}

fn read_byte_vec<R: Read>(
    reader: &mut R,
    len: usize,
    field_name: &str,
) -> Result<Vec<u8>> {
    const MAX_BYTE_VEC_LEN: usize = 512 * 1024 * 1024; // 512 MiB limit
    if len > MAX_BYTE_VEC_LEN {
        bail!(
            "{} data length ({}) exceeds maximum allowed size ({})",
            field_name,
            len,
            MAX_BYTE_VEC_LEN
        );
    }
    let mut vec = vec![0u8; len];
    reader.read_exact(&mut vec).with_context(|| {
        format!("Failed to read {field_name} data ({len} bytes)")
    })?;
    Ok(vec)
}

// --- Range to CIDR Conversion Logic ---

/// Converts an inclusive IP address range [start, end] into a minimal list of
/// CIDR prefixes using an optimized algorithm.
fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Result<Vec<IpNet>> {
    if start > end {
        return Ok(Vec::new()); // Empty range
    }

    // Normalize IPv4-mapped IPv6 addresses
    let normalize = |ip: IpAddr| -> IpAddr {
        match ip {
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(v6)
                }
            }
            v4 => v4,
        }
    };

    let start = normalize(start);
    let end = normalize(end);

    // Ensure start and end are the same address family
    if start.is_ipv4() != end.is_ipv4() {
        bail!("Start and end IP addresses must be of the same family");
    }

    match (start, end) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            range_to_cidrs_v4(start_v4, end_v4)
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            range_to_cidrs_v6(start_v6, end_v6)
        }
        _ => unreachable!("Already checked address family"),
    }
}

fn range_to_cidrs_v4(start: Ipv4Addr, end: Ipv4Addr) -> Result<Vec<IpNet>> {
    let mut result = Vec::new();
    let mut current = u32::from(start);
    let end_u32 = u32::from(end);

    while current <= end_u32 {
        // Find the largest CIDR block starting at current that fits within the
        // range

        // 1. Find alignment: how many trailing zeros does current have?
        let trailing_zeros = if current == 0 {
            32
        } else {
            current.trailing_zeros()
        };

        // 2. Find the largest block size that fits in the remaining range
        let remaining_ips = end_u32 - current + 1;

        // Find the largest power of 2 that is <= remaining_ips
        // Note: remaining_ips is always >= 1 due to loop condition
        let max_block_size_bits = 31 - remaining_ips.leading_zeros();

        // Take the minimum: we can't use more bits than alignment allows
        let block_size_bits = trailing_zeros.min(max_block_size_bits);
        let prefix_len = 32 - block_size_bits;

        let cidr =
            IpNet::new(IpAddr::V4(Ipv4Addr::from(current)), prefix_len as u8)?;
        result.push(cidr);

        // Move to next block
        let block_size = 1u64 << block_size_bits;
        let next = current as u64 + block_size;
        if next > end_u32 as u64 || next > u32::MAX as u64 {
            break;
        }
        current = next as u32;
    }

    Ok(result)
}

fn range_to_cidrs_v6(start: Ipv6Addr, end: Ipv6Addr) -> Result<Vec<IpNet>> {
    let mut result = Vec::new();
    let mut current = u128::from(start);
    let end_u128 = u128::from(end);

    while current <= end_u128 {
        // Find the largest CIDR block starting at current that fits within the
        // range

        // 1. Find alignment: how many trailing zeros does current have?
        let trailing_zeros = if current == 0 {
            128
        } else {
            current.trailing_zeros()
        };

        // 2. Find the largest block size that fits in the remaining range
        let remaining_ips = end_u128 - current + 1;

        // Find the largest power of 2 that is <= remaining_ips
        // Note: remaining_ips is always >= 1 due to loop condition
        let max_block_size_bits = 127 - remaining_ips.leading_zeros();

        // Take the minimum: we can't use more bits than alignment allows
        let block_size_bits = trailing_zeros.min(max_block_size_bits);
        let prefix_len = 128 - block_size_bits;

        let cidr =
            IpNet::new(IpAddr::V6(Ipv6Addr::from(current)), prefix_len as u8)?;
        result.push(cidr);

        // Move to next block
        debug_assert!(
            block_size_bits < 128,
            "block_size_bits should always be less than 128"
        );
        let block_size = 1u128 << block_size_bits;

        match current.checked_add(block_size) {
            Some(next) if next <= end_u128 => current = next,
            _ => break,
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_range_to_cidrs_single_ip_v4() {
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.1/32");
    }

    #[test]
    fn test_range_to_cidrs_aligned_block_v4() {
        // 192.168.1.0 - 192.168.1.255 is a perfect /24
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_range_to_cidrs_unaligned_v4() {
        // 192.168.1.1 - 192.168.1.5 should split into multiple CIDRs
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let result = range_to_cidrs(start, end).unwrap();

        // Expected: 192.168.1.1/32, 192.168.1.2/31, 192.168.1.4/31
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].to_string(), "192.168.1.1/32");
        assert_eq!(result[1].to_string(), "192.168.1.2/31");
        assert_eq!(result[2].to_string(), "192.168.1.4/31");
    }

    #[test]
    fn test_range_to_cidrs_large_range_v4() {
        // 10.0.0.0 - 10.255.255.255 is a perfect /8
        let start = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let end = IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_range_to_cidrs_cross_boundary_v4() {
        // 192.168.0.255 - 192.168.2.1
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1));
        let result = range_to_cidrs(start, end).unwrap();

        // Should produce multiple CIDRs
        assert!(!result.is_empty());

        // Verify all IPs in range are covered
        let mut covered_ips = vec![];
        for cidr in &result {
            for addr in cidr.hosts() {
                covered_ips.push(addr);
            }
        }

        // Check first and last are covered
        assert!(covered_ips.contains(&start));
        assert!(covered_ips.contains(&end));
    }

    #[test]
    fn test_range_to_cidrs_empty_range() {
        // end < start should return empty
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_range_to_cidrs_ipv4_mapped_ipv6() {
        // IPv4-mapped IPv6 addresses should be normalized to IPv4
        let start = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0100));
        let end = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x01ff));
        let result = range_to_cidrs(start, end).unwrap();

        // Should be normalized to 192.168.1.0/24
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_range_to_cidrs_single_ip_v6() {
        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "2001:db8::1/128");
    }

    #[test]
    fn test_range_to_cidrs_aligned_block_v6() {
        // 2001:db8::/32 block
        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let end = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_range_to_cidrs_small_range_v6() {
        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5));
        let result = range_to_cidrs(start, end).unwrap();

        // Expected: 2001:db8::1/128, 2001:db8::2/127, 2001:db8::4/127
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].to_string(), "2001:db8::1/128");
        assert_eq!(result[1].to_string(), "2001:db8::2/127");
        assert_eq!(result[2].to_string(), "2001:db8::4/127");

        // Verify the total number of IPs covered matches the range
        let total_ips: u128 = result
            .iter()
            .map(|cidr| 1u128 << (128 - cidr.prefix_len()))
            .sum();
        assert_eq!(total_ips, 5u128); // IPs 1-5 inclusive
    }

    #[test]
    fn test_range_to_cidrs_mixed_family_error() {
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = range_to_cidrs(start, end);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_to_cidrs_single_remaining_ip_v4() {
        // Test the edge case mentioned in Copilot comment: remaining_ips = 1
        // When we have exactly 1 IP left, leading_zeros() = 31
        // max_block_size_bits should be 31 - 31 = 0, giving block_size = 2^0 =
        // 1 IP
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)); // Same IP
        let result = range_to_cidrs(start, end).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.100/32"); // Single IP

        // Verify exactly 1 IP is covered
        let total_ips: u64 = result
            .iter()
            .map(|cidr| 1u64 << (32 - cidr.prefix_len()))
            .sum();
        assert_eq!(total_ips, 1);
    }

    #[test]
    fn test_range_to_cidrs_single_remaining_ip_v6() {
        // Test the edge case for IPv6: remaining_ips = 1
        // When we have exactly 1 IP left, leading_zeros() = 127
        // max_block_size_bits should be 127 - 127 = 0, giving block_size = 2^0
        // = 1 IP
        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100));
        let end = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100)); // Same IP
        let result = range_to_cidrs(start, end).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "2001:db8::64/128"); // Single IP

        // Verify exactly 1 IP is covered
        let total_ips: u128 = result
            .iter()
            .map(|cidr| 1u128 << (128 - cidr.prefix_len()))
            .sum();
        assert_eq!(total_ips, 1u128);
    }

    #[test]
    fn test_range_to_cidrs_two_remaining_ips_v4() {
        // Test remaining_ips = 2: leading_zeros() = 30
        // max_block_size_bits should be 31 - 30 = 1, giving block_size = 2^1 =
        // 2 IPs
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)); // 2 IPs
        let result = range_to_cidrs(start, end).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.100/31"); // 2 IPs

        // Verify exactly 2 IPs are covered
        let total_ips: u64 = result
            .iter()
            .map(|cidr| 1u64 << (32 - cidr.prefix_len()))
            .sum();
        assert_eq!(total_ips, 2);
    }

    #[test]
    fn test_range_to_cidrs_small_ipv6_prefix_shift_overflow() {
        // Test the potential shift overflow issue mentioned in Copilot comments
        // Create a large IPv6 range that would cause overflow with u64 shifts
        let start = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let end = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ));
        let result = range_to_cidrs(start, end).unwrap();

        // This should produce a /32 CIDR covering 2^96 IPs
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "2001:db8::/32");

        // This would overflow with u64, so we need u128
        let total_ips: u128 = result
            .iter()
            .map(|cidr| 1u128 << (128 - cidr.prefix_len()))
            .sum();
        assert_eq!(total_ips, 1u128 << 96); // 2^96 IPs

        // Demonstrate that u64 would overflow for this case
        // (This is just a comment to show why we need u128)
        // let would_overflow: u64 = 1u64 << (128 - 32); // This would panic!
    }

    #[test]
    fn test_bit_calculation_edge_cases() {
        // Test various remaining_ips values to verify bit calculations
        let test_cases = vec![
            (1u32, 0u32),  // remaining=1, leading_zeros=31, expected_bits=0
            (2u32, 1u32),  // remaining=2, leading_zeros=30, expected_bits=1
            (4u32, 2u32),  // remaining=4, leading_zeros=29, expected_bits=2
            (8u32, 3u32),  // remaining=8, leading_zeros=28, expected_bits=3
            (16u32, 4u32), // remaining=16, leading_zeros=27, expected_bits=4
        ];

        for (remaining_ips, expected_bits) in test_cases {
            let calculated_bits = 31 - remaining_ips.leading_zeros();
            assert_eq!(
                calculated_bits, expected_bits,
                "For remaining_ips={}, expected {} bits but got {}",
                remaining_ips, expected_bits, calculated_bits
            );
        }
    }

    #[test]
    fn test_range_to_cidrs_max_ip_v4() {
        // Test range ending at maximum IPv4 address
        let start = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254));
        let end = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "255.255.255.254/31");
    }

    #[test]
    fn test_range_to_cidrs_power_of_two_v4() {
        // Range of exactly 256 IPs starting at aligned address
        let start = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let end = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));
        let result = range_to_cidrs(start, end).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "10.0.0.0/24");
    }

    #[test]
    fn test_range_to_cidrs_coverage_v4() {
        // Comprehensive test: verify all IPs in range are covered exactly once
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let result = range_to_cidrs(start, end).unwrap();

        // Just verify the result is non-empty and contains some expected CIDRs
        assert!(!result.is_empty());

        // Verify the total number of IPs covered matches the range
        let total_ips: u64 = result
            .iter()
            .map(|cidr| 1u64 << (32 - cidr.prefix_len()))
            .sum();
        assert_eq!(total_ips, 101); // 100 to 200 inclusive
    }
}
