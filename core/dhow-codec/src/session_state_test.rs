//! Tests for the session state machine.

use crate::session::{RaptorQParams, SessionParams};
use crate::session_state::{SessionState, SessionStateMachine};

/// Builds session parameters with 4 source and 8 total symbols across 2 blocks.
fn test_params() -> SessionParams {
    SessionParams {
        payload_size: 1024,
        block_count: 2,
        symbol_size: 256,
        source_symbols_per_block: 4,
        total_symbols_per_block: 8,
        raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
        payload_digest: [0u8; 32],
    }
}

fn machine() -> SessionStateMachine {
    SessionStateMachine::new([7u8; 16], test_params())
}

#[test]
fn test_new_starts_initializing() {
    let sm = machine();
    assert_eq!(sm.state(), SessionState::Initializing);
    assert_eq!(sm.frames_sent(), 0);
    assert_eq!(sm.frames_received(), 0);
    assert_eq!(sm.bytes_transmitted(), 0);
    assert!(sm.last_error().is_none());
}

#[test]
fn test_default_state_is_initializing() {
    assert_eq!(SessionState::default(), SessionState::Initializing);
}

#[test]
fn test_accessors_return_construction_values() {
    let sm = machine();
    assert_eq!(sm.session_id(), [7u8; 16]);
    assert_eq!(sm.params().payload_size, 1024);
    assert_eq!(sm.params().block_count, 2);
}

#[test]
fn test_start_sending_from_initializing() {
    let mut sm = machine();
    assert!(sm.start_sending().is_ok());
    assert_eq!(sm.state(), SessionState::Sending);
}

#[test]
fn test_start_receiving_from_initializing() {
    let mut sm = machine();
    assert!(sm.start_receiving().is_ok());
    assert_eq!(sm.state(), SessionState::Receiving);
}

#[test]
fn test_start_receiving_rejected_once_sending() {
    let mut sm = machine();
    sm.start_sending().unwrap();
    assert!(sm.start_receiving().is_err());
    // The rejected transition must not move the machine.
    assert_eq!(sm.state(), SessionState::Sending);
}

#[test]
fn test_start_sending_rejected_once_receiving() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    assert!(sm.start_sending().is_err());
    assert_eq!(sm.state(), SessionState::Receiving);
}

#[test]
fn test_pause_and_resume_sending() {
    let mut sm = machine();
    sm.start_sending().unwrap();
    assert!(sm.pause().is_ok());
    assert_eq!(sm.state(), SessionState::Paused);
    assert!(sm.start_sending().is_ok());
    assert_eq!(sm.state(), SessionState::Sending);
}

#[test]
fn test_pause_from_receiving() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    assert!(sm.pause().is_ok());
    assert_eq!(sm.state(), SessionState::Paused);
}

#[test]
fn test_pause_rejected_from_initializing() {
    let mut sm = machine();
    assert!(sm.pause().is_err());
    assert_eq!(sm.state(), SessionState::Initializing);
}

#[test]
fn test_enter_recovery_from_receiving() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    assert!(sm.enter_recovery().is_ok());
    assert_eq!(sm.state(), SessionState::Recovering);
}

#[test]
fn test_enter_recovery_rejected_from_initializing() {
    let mut sm = machine();
    assert!(sm.enter_recovery().is_err());
    assert_eq!(sm.state(), SessionState::Initializing);
}

#[test]
fn test_complete_from_receiving() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    assert!(sm.complete().is_ok());
    assert_eq!(sm.state(), SessionState::Complete);
}

#[test]
fn test_complete_from_recovering() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    sm.enter_recovery().unwrap();
    assert!(sm.complete().is_ok());
    assert_eq!(sm.state(), SessionState::Complete);
}

#[test]
fn test_complete_rejected_from_initializing() {
    let mut sm = machine();
    assert!(sm.complete().is_err());
    assert_eq!(sm.state(), SessionState::Initializing);
}

#[test]
fn test_complete_is_terminal() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    sm.complete().unwrap();
    assert!(sm.start_sending().is_err());
    assert!(sm.start_receiving().is_err());
    assert!(sm.pause().is_err());
    assert!(sm.enter_recovery().is_err());
    assert!(sm.complete().is_err());
    assert_eq!(sm.state(), SessionState::Complete);
}

#[test]
fn test_error_records_reason_and_is_terminal() {
    let mut sm = machine();
    sm.start_receiving().unwrap();
    sm.error("frame MAC verification failed");
    assert_eq!(sm.state(), SessionState::Error);
    assert_eq!(sm.last_error(), Some("frame MAC verification failed"));
    // No transition escapes the error state.
    assert!(sm.complete().is_err());
    assert!(sm.start_receiving().is_err());
    assert_eq!(sm.state(), SessionState::Error);
}

#[test]
fn test_error_overwrites_previous_reason() {
    let mut sm = machine();
    sm.error("first");
    sm.error("second");
    assert_eq!(sm.last_error(), Some("second"));
}

#[test]
fn test_record_frame_sent_accumulates() {
    let mut sm = machine();
    sm.record_frame_sent(100);
    sm.record_frame_sent(250);
    assert_eq!(sm.frames_sent(), 2);
    assert_eq!(sm.bytes_transmitted(), 350);
    // Sent frames must not be counted as received.
    assert_eq!(sm.frames_received(), 0);
}

#[test]
fn test_record_frame_received_accumulates() {
    let mut sm = machine();
    sm.record_frame_received();
    sm.record_frame_received();
    assert_eq!(sm.frames_received(), 2);
    assert_eq!(sm.bytes_transmitted(), 0);
}

#[test]
fn test_progress_zero_before_any_frames() {
    let sm = machine();
    assert_eq!(sm.progress(), 0.0);
}

#[test]
fn test_progress_is_fraction_of_source_symbols() {
    let mut sm = machine();
    // 4 source symbols x 2 blocks = 8 needed.
    for _ in 0..2 {
        sm.record_frame_received();
    }
    assert!((sm.progress() - 0.25).abs() < f64::EPSILON);
}

#[test]
fn test_progress_saturates_at_one() {
    let mut sm = machine();
    // Feed far more than the 8 needed; repair symbols must not exceed 100%.
    for _ in 0..64 {
        sm.record_frame_received();
    }
    assert_eq!(sm.progress(), 1.0);
}

#[test]
fn test_progress_is_one_for_empty_payload() {
    let mut params = test_params();
    params.payload_size = 0;
    let sm = SessionStateMachine::new([1u8; 16], params);
    assert_eq!(sm.progress(), 1.0);
}

#[test]
fn test_progress_does_not_divide_by_zero() {
    let mut params = test_params();
    params.source_symbols_per_block = 0;
    let sm = SessionStateMachine::new([1u8; 16], params);
    assert_eq!(sm.progress(), 1.0);
}

#[test]
fn test_progress_no_overflow_on_large_session() {
    // Guards the u32 multiplication that overflowed before it was widened.
    let mut params = test_params();
    params.source_symbols_per_block = u32::MAX;
    params.block_count = u32::MAX;
    let sm = SessionStateMachine::new([1u8; 16], params);
    assert_eq!(sm.progress(), 0.0);
}
