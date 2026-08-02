//! Session state machine for Dhow transfers.
//!
//! Manages the state transitions of a transfer session:
//! initializing, sending/receiving frames, FEC recovery,
//! completion, and error handling.
//!
//! # States
//!
//! - **Initializing**: Session parameters set, no frames processed yet.
//! - **Sending**/**Receiving**: Active frame transfer in progress.
//! - **Recovering**: FEC recovery from packet loss.
//! - **Complete**: All frames received and payload reconstructed.
//! - **Error**: An error occurred during transfer.
//!
//! # Example
//!
//! ```
//! use dhow_codec::session_state::{SessionStateMachine, SessionState};
//! use dhow_codec::session::{SessionParams, RaptorQParams};
//!
//! let params = SessionParams {
//!     payload_size: 55,
//!     block_count: 1,
//!     symbol_size: 256,
//!     source_symbols_per_block: 1,
//!     total_symbols_per_block: 2,
//!     raptorq: RaptorQParams { z: 1, n: 1, psi: 1 },
//!     payload_digest: [0u8; 32],
//! };
//! let mut state = SessionStateMachine::new([0; 16], params);
//! assert_eq!(state.state(), SessionState::Initializing);
//! state.start_sending();
//! assert_eq!(state.state(), SessionState::Sending);
//! ```

use crate::SessionError;
use crate::session::SessionParams;

/// The current state of a transfer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Session initialized but no transfer started.
    #[default]
    Initializing,
    /// Sender is actively transmitting frames.
    Sending,
    /// Receiver is actively waiting for frames.
    Receiving,
    /// FEC recovery in progress (lost frames being reconstructed).
    Recovering,
    /// Transfer complete, payload reconstructed.
    Complete,
    /// An error occurred during the transfer.
    Error,
    /// Transfer paused (for resume).
    Paused,
}

/// A state machine that tracks the progress of a Dhow transfer.
pub struct SessionStateMachine {
    session_id: [u8; 16],
    params: SessionParams,
    state: SessionState,
    frames_sent: u64,
    frames_received: u64,
    bytes_transmitted: u64,
    last_error: Option<String>,
}

impl SessionStateMachine {
    /// Creates a new session state machine in the `Initializing` state.
    pub fn new(session_id: [u8; 16], params: SessionParams) -> Self {
        Self {
            session_id,
            params,
            state: SessionState::Initializing,
            frames_sent: 0,
            frames_received: 0,
            bytes_transmitted: 0,
            last_error: None,
        }
    }

    /// Transitions to the `Sending` state (sender side).
    pub fn start_sending(&mut self) -> Result<(), SessionError> {
        match self.state {
            SessionState::Initializing | SessionState::Paused => {
                self.state = SessionState::Sending;
                Ok(())
            }
            _ => Err(SessionError::InvalidParameters {
                details: format!("cannot start sending from {:?}", self.state),
            }),
        }
    }

    /// Transitions to the `Receiving` state (receiver side).
    pub fn start_receiving(&mut self) -> Result<(), SessionError> {
        match self.state {
            SessionState::Initializing => {
                self.state = SessionState::Receiving;
                Ok(())
            }
            _ => Err(SessionError::InvalidParameters {
                details: format!("cannot start receiving from {:?}", self.state),
            }),
        }
    }

    /// Transitions to the `Recovering` state (FEC recovery).
    pub fn enter_recovery(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, SessionState::Receiving | SessionState::Sending) {
            self.state = SessionState::Recovering;
            Ok(())
        } else {
            Err(SessionError::InvalidParameters {
                details: format!("cannot enter recovery from {:?}", self.state),
            })
        }
    }

    /// Transitions to the `Complete` state.
    ///
    /// Completion is reachable from an active transfer or from FEC recovery,
    /// since a recovered block finishes the transfer just as a fully received
    /// one does.
    pub fn complete(&mut self) -> Result<(), SessionError> {
        if matches!(
            self.state,
            SessionState::Sending | SessionState::Receiving | SessionState::Recovering
        ) {
            self.state = SessionState::Complete;
            Ok(())
        } else {
            Err(SessionError::InvalidParameters {
                details: format!("cannot complete from {:?}", self.state),
            })
        }
    }

    /// Transitions to the `Error` state, recording a reason.
    ///
    /// The reason is a control-path description only. Callers must never pass
    /// payload bytes or key material here.
    pub fn error(&mut self, error: &str) {
        self.state = SessionState::Error;
        self.last_error = Some(error.to_string());
    }

    /// Returns the reason recorded by the most recent [`Self::error`] call.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Pauses the transfer (switches to `Paused` state).
    pub fn pause(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, SessionState::Sending | SessionState::Receiving) {
            self.state = SessionState::Paused;
            Ok(())
        } else {
            Err(SessionError::InvalidParameters {
                details: format!("cannot pause from {:?}", self.state),
            })
        }
    }

    /// Records that a frame was sent.
    pub fn record_frame_sent(&mut self, frame_size: usize) {
        self.frames_sent += 1;
        self.bytes_transmitted += frame_size as u64;
    }

    /// Records that a frame was received.
    pub fn record_frame_received(&mut self) {
        self.frames_received += 1;
    }

    /// Returns the current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Returns the session parameters.
    pub fn params(&self) -> &SessionParams {
        &self.params
    }

    /// Returns the number of frames sent.
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Returns the number of frames received.
    pub fn frames_received(&self) -> u64 {
        self.frames_received
    }

    /// Returns the number of bytes transmitted.
    pub fn bytes_transmitted(&self) -> u64 {
        self.bytes_transmitted
    }

    /// Returns receive progress as a fraction in `0.0..=1.0`.
    ///
    /// The denominator is the number of *source* symbols in the session, which
    /// is the theoretical minimum needed to decode. RaptorQ needs a small
    /// overhead above that, so this is an estimate for display and saturates at
    /// 1.0; it is never a completion signal. Use [`Self::state`] for that.
    pub fn progress(&self) -> f64 {
        if self.params.payload_size == 0 {
            return 1.0;
        }
        let needed =
            u64::from(self.params.source_symbols_per_block) * u64::from(self.params.block_count);
        if needed == 0 {
            return 1.0;
        }
        (self.frames_received as f64 / needed as f64).min(1.0)
    }
}
