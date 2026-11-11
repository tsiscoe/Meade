use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::db::models::{Tier1Header, Tier2Secret};
use crate::totp::generate_totp_now;

/// Represents a single stage in the sequential multi-copy clipboard queue (`Ctrl+Shift+V`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueStageKind {
    Identity,
    PrimarySecret,
    TotpCode,
}

impl QueueStageKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Identity => "Stage 1: Identity / Username",
            Self::PrimarySecret => "Stage 2: Primary Secret / Key",
            Self::TotpCode => "Stage 3: Live RFC 6238 TOTP",
        }
    }
}

/// Internal zeroizing item in the sequential clipboard queue.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct QueueStep {
    #[zeroize(skip)]
    kind: QueueStageKind,
    value: String,
    is_live_totp_seed: bool,
}

/// Publicly serializable status snapshot of the active sequential clipboard queue for the TUI footer & CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueStatusSnapshot {
    pub active: bool,
    pub entry_title: String,
    pub current_stage_index: usize,
    pub total_stages: usize,
    pub current_stage_label: String,
    pub remaining_ttl_secs: u64,
}

impl Default for QueueStatusSnapshot {
    fn default() -> Self {
        Self {
            active: false,
            entry_title: String::new(),
            current_stage_index: 0,
            total_stages: 0,
            current_stage_label: "Idle (Clipboard Clean)".to_string(),
            remaining_ttl_secs: 0,
        }
    }
}

/// State machine driving the `Username -> Password -> TOTP -> Auto-Scrub` sequential clipboard pipeline.
/// Pressing `Ctrl+Shift+V` (or invoking `advance_stage()`) transitions to the next stage and writes
/// the new secret to the OS clipboard; advancing past the final stage or hitting the TTL deadline
/// triggers an immediate cryptographic clipboard scrub.
pub struct SequentialPasteQueue {
    entry_title: String,
    steps: Vec<QueueStep>,
    cursor: usize,
    stage_loaded_at: Option<Instant>,
    ttl: Duration,
}

impl SequentialPasteQueue {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entry_title: String::new(),
            steps: Vec::new(),
            cursor: 0,
            stage_loaded_at: None,
            ttl: Duration::from_secs(ttl_secs.max(5)),
        }
    }

    /// Enqueues a full credential lifecycle (`Identity -> PrimarySecret -> TOTP`) and returns
    /// the immediate first payload to place on the OS clipboard.
    pub fn load_credential(
        &mut self,
        header: &Tier1Header,
        secret: &Tier2Secret,
    ) -> Option<(QueueStageKind, String)> {
        self.clear();
        self.entry_title = header.title.clone();

        if !header.identity.trim().is_empty() {
            self.steps.push(QueueStep {
                kind: QueueStageKind::Identity,
                value: header.identity.clone(),
                is_live_totp_seed: false,
            });
        }

        if !secret.primary_secret.is_empty() {
            self.steps.push(QueueStep {
                kind: QueueStageKind::PrimarySecret,
                value: secret.primary_secret.clone(),
                is_live_totp_seed: false,
            });
        }

        if let Some(totp_seed) = &secret.totp_secret
            && !totp_seed.trim().is_empty()
        {
            self.steps.push(QueueStep {
                kind: QueueStageKind::TotpCode,
                value: totp_seed.clone(),
                is_live_totp_seed: true,
            });
        }

        if self.steps.is_empty() {
            return None;
        }

        self.cursor = 0;
        self.stage_loaded_at = Some(Instant::now());
        self.resolve_current_payload()
    }

    /// Loads a single one-off secret (e.g., `y` to copy password only or `t` for TOTP only) with auto-scrub TTL.
    pub fn load_single_step(
        &mut self,
        title: &str,
        kind: QueueStageKind,
        value: String,
        is_live_totp_seed: bool,
    ) -> Option<(QueueStageKind, String)> {
        self.clear();
        self.entry_title = title.to_string();
        self.steps.push(QueueStep {
            kind,
            value,
            is_live_totp_seed,
        });
        self.cursor = 0;
        self.stage_loaded_at = Some(Instant::now());
        self.resolve_current_payload()
    }

    /// Advances the queue to the next stage (triggered by `Ctrl+Shift+V` or `meade queue next`).
    /// Returns `Some((kind, payload))` if a new stage is now active, or `None` if the queue finished
    /// and the clipboard should now be scrubbed.
    pub fn advance(&mut self) -> Option<(QueueStageKind, String)> {
        if self.steps.is_empty() {
            return None;
        }
        self.cursor += 1;
        if self.cursor >= self.steps.len() {
            self.clear();
            return None;
        }
        self.stage_loaded_at = Some(Instant::now());
        self.resolve_current_payload()
    }

    /// Checks if the current stage's TTL has expired. If expired, clears the queue and returns `true`
    /// so the caller scrubs the OS clipboard.
    pub fn check_expired(&mut self) -> bool {
        if let Some(loaded_at) = self.stage_loaded_at
            && loaded_at.elapsed() >= self.ttl
        {
            self.clear();
            return true;
        }
        false
    }

    /// Wipes all queued secrets in memory.
    pub fn clear(&mut self) {
        self.steps.clear();
        self.entry_title.clear();
        self.cursor = 0;
        self.stage_loaded_at = None;
    }

    pub fn is_active(&self) -> bool {
        !self.steps.is_empty() && self.cursor < self.steps.len()
    }

    pub fn status(&self) -> QueueStatusSnapshot {
        if !self.is_active() {
            return QueueStatusSnapshot::default();
        }
        let step = &self.steps[self.cursor];
        let elapsed = self.stage_loaded_at.map_or(Duration::ZERO, |t| t.elapsed());
        let remaining = self.ttl.saturating_sub(elapsed).as_secs();

        QueueStatusSnapshot {
            active: true,
            entry_title: self.entry_title.clone(),
            current_stage_index: self.cursor + 1,
            total_stages: self.steps.len(),
            current_stage_label: step.kind.label().to_string(),
            remaining_ttl_secs: remaining,
        }
    }

    fn resolve_current_payload(&self) -> Option<(QueueStageKind, String)> {
        let step = self.steps.get(self.cursor)?;
        if step.is_live_totp_seed {
            let code = generate_totp_now(&step.value)
                .map(|snap| snap.code)
                .unwrap_or_else(|_| "000000".to_string());
            Some((step.kind.clone(), code))
        } else {
            Some((step.kind.clone(), step.value.clone()))
        }
    }
}
