//! Round-trip tests for FEC encoding and decoding.

#[cfg(test)]
mod tests {
    use crate::fec;
    use proptest::prelude::*;

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
