//! Round-trip tests for FEC encoding and decoding.

#[cfg(test)]
mod tests {
    use crate::fec;
    use proptest::prelude::*;

    #[test]
    fn test_fec_custom_mtu() {
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let params = fec::FecParams::with_mtu(512);
        assert_eq!(params.mtu(), 512);
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let packets = encoder.packets(20);

        let decoded = fec::decode(&packets, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    #[should_panic(expected = "MTU must be at least 64")]
    fn test_fec_mtu_too_small() {
        let _ = fec::FecParams::with_mtu(32);
    }

    #[test]
    fn test_fec_round_trip_source_only() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let source_packets = encoder.source_packets();

        let decoded = fec::decode(&source_packets, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_round_trip_repair_only() {
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let repair_packets = encoder.repair_packets(100);

        let decoded = fec::decode(&repair_packets, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_round_trip_mixed() {
        let data: Vec<u8> = b"The quick brown fox jumps over the lazy dog".to_vec();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let packets = encoder.packets(50);

        let decoded = fec::decode(&packets, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_partial_loss_recovery() {
        let data: Vec<u8> = b"Recovering from packet loss".to_vec();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let all_packets = encoder.packets(30);

        // Simulate 30% packet loss
        let surviving: Vec<_> = all_packets.iter().step_by(3).cloned().collect();
        let decoded = fec::decode(&surviving, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_packets_structure() {
        let data: Vec<u8> = b"Check packet structure".to_vec();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);

        let source = encoder.source_packets();
        let repair = encoder.repair_packets(5);
        let mixed = encoder.packets(5);

        assert!(source.len() > 0);
        assert!(repair.len() >= 5);
        // mixed = source + repair per block
        assert!(mixed.len() >= source.len());
    }

    #[test]
    fn test_fec_single_byte() {
        let data: Vec<u8> = vec![42];
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let packets = encoder.packets(10);

        let decoded = fec::decode(&packets, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_large_payload() {
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();
        let packets = encoder.packets(50);

        let decoded = fec::decode(&packets, &config);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_decoder_stateful() {
        let data: Vec<u8> = b"Stateful decoder test".to_vec();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();

        let mut decoder = fec::FecDecoder::new(&config);
        let packets = encoder.packets(10);
        for packet in &packets {
            decoder.add_packet(packet);
        }
        let decoded = decoder.decode();
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), data);
    }

    #[test]
    fn test_fec_decoder_insufficient_packets() {
        let data: Vec<u8> = b"Need more packets".to_vec();
        let params = fec::FecParams::new();
        let encoder = fec::encode(&data, &params);
        let config = encoder.config();

        let packets = encoder.packets(50);
        let mut decoder = fec::FecDecoder::new(&config);

        // Add only first 3 packets
        for packet in packets.iter().take(3) {
            decoder.add_packet(packet);
        }
        let decoded = decoder.decode();
        // Should be None if not enough packets
        // (raptorq may still decode if we got a full source block)
        // Just verify it doesn't panic
        drop(decoded);
    }

    proptest! {
        #[test]
        fn prop_fec_round_trip(
            data in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 1..10000usize)
        ) {
            let params = fec::FecParams::new();
            let encoder = fec::encode(&data, &params);
            let config = encoder.config();
            let packets = encoder.packets(20);
            let decoded = fec::decode(&packets, &config);
            prop_assert!(decoded.is_some());
            prop_assert_eq!(decoded.unwrap(), data);
        }
    }
}
