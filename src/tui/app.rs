use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use ratatui::widgets::TableState;

use crate::crypto::VaultKeys;
use crate::daemon::clipboard::{scrub_clipboard, write_secret_to_clipboard};
use crate::daemon::queue::{QueueStageKind, QueueStatusSnapshot, SequentialPasteQueue};
use crate::db::VaultDb;
use crate::db::models::{CatalogueItem, SecretCategory, Tier1Header, Tier2Secret};
use crate::error::Result;
use crate::totp::{TotpSnapshot, generate_totp_now};

/// Category filter tabs in the left sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryFilter {
    All,
    Category(SecretCategory),
}

impl CategoryFilter {
    pub fn all_filters() -> &'static [CategoryFilter] {
        &[
            CategoryFilter::All,
            CategoryFilter::Category(SecretCategory::Login),
            CategoryFilter::Category(SecretCategory::ApiKey),
            CategoryFilter::Category(SecretCategory::SshKey),
            CategoryFilter::Category(SecretCategory::TotpOnly),
            CategoryFilter::Category(SecretCategory::SecureNote),
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All Vault Items",
            Self::Category(c) => c.label(),
        }
    }
}

/// Active input mode of the Ratatui Catalogue Viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Search,
    AddModal,
    ConfirmDelete,
}

/// Editable fields in the "New Credential" modal dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalField {
    Title,
    Category,
    Identity,
    UrlOrHost,
    Tags,
    PrimarySecret,
    TotpSecret,
    Notes,
}

impl ModalField {
    pub fn next(self) -> Self {
        match self {
            Self::Title => Self::Category,
            Self::Category => Self::Identity,
            Self::Identity => Self::UrlOrHost,
            Self::UrlOrHost => Self::Tags,
            Self::Tags => Self::PrimarySecret,
            Self::PrimarySecret => Self::TotpSecret,
            Self::TotpSecret => Self::Notes,
            Self::Notes => Self::Title,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Title => Self::Notes,
            Self::Category => Self::Title,
            Self::Identity => Self::Category,
            Self::UrlOrHost => Self::Identity,
            Self::Tags => Self::UrlOrHost,
            Self::PrimarySecret => Self::Tags,
            Self::TotpSecret => Self::PrimarySecret,
            Self::Notes => Self::TotpSecret,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DraftEntryForm {
    pub active_field: ModalField,
    pub title: String,
    pub category_idx: usize,
    pub identity: String,
    pub url_or_host: String,
    pub tags_csv: String,
    pub primary_secret: String,
    pub totp_secret: String,
    pub notes: String,
}

impl Default for DraftEntryForm {
    fn default() -> Self {
        Self {
            active_field: ModalField::Title,
            title: String::new(),
            category_idx: 0,
            identity: String::new(),
            url_or_host: String::new(),
            tags_csv: String::new(),
            primary_secret: String::new(),
            totp_secret: String::new(),
            notes: String::new(),
        }
    }
}

impl DraftEntryForm {
    pub fn selected_category(&self) -> SecretCategory {
        let all = SecretCategory::all();
        all[self.category_idx % all.len()]
    }
}

/// Primary state machine for the Meade Ratatui v0.30+ Catalogue Viewer (The Elm Architecture).
pub struct TuiApp {
    pub db: VaultDb,
    pub keys: VaultKeys,
    pub running: bool,
    pub mode: InputMode,
    pub category_filter_idx: usize,
    pub search_query: String,
    pub all_items: Vec<CatalogueItem>,
    pub filtered_items: Vec<CatalogueItem>,
    pub table_state: TableState,
    pub reveal_secret: bool,
    pub inspected_secret: Option<(String, Tier2Secret)>,
    pub live_totp: Option<TotpSnapshot>,
    pub local_queue: SequentialPasteQueue,
    pub queue_snapshot: QueueStatusSnapshot,
    pub status_toast: String,
    pub draft_form: DraftEntryForm,
    pub headless_clipboard: bool,
}

impl TuiApp {
    pub fn new(db: VaultDb, keys: VaultKeys, headless_clipboard: bool) -> Result<Self> {
        let all_items = db.list_catalogue(&keys)?;
        let mut app = Self {
            db,
            keys,
            running: true,
            mode: InputMode::Normal,
            category_filter_idx: 0,
            search_query: String::new(),
            all_items,
            filtered_items: Vec::new(),
            table_state: TableState::default(),
            reveal_secret: false,
            inspected_secret: None,
            live_totp: None,
            local_queue: SequentialPasteQueue::new(20),
            queue_snapshot: QueueStatusSnapshot::default(),
            status_toast: "Meade Vault Unlocked // Enter: Queue (User->Pass->TOTP) | Ctrl+Shift+V: Next Stage | /: Search | a: Add".to_string(),
            draft_form: DraftEntryForm::default(),
            headless_clipboard,
        };
        app.recompute_filter();
        app.refresh_totp_and_queue();
        Ok(app)
    }

    pub fn current_filter(&self) -> CategoryFilter {
        let filters = CategoryFilter::all_filters();
        filters[self.category_filter_idx % filters.len()]
    }

    pub fn selected_item(&self) -> Option<&CatalogueItem> {
        let idx = self.table_state.selected()?;
        self.filtered_items.get(idx)
    }

    pub fn recompute_filter(&mut self) {
        let matcher = SkimMatcherV2::default();
        let filter = self.current_filter();
        let query = self.search_query.trim();

        let mut scored: Vec<(i64, CatalogueItem)> = self
            .all_items
            .iter()
            .filter(|item| match filter {
                CategoryFilter::All => true,
                CategoryFilter::Category(cat) => item.header.category == cat,
            })
            .filter_map(|item| {
                if query.is_empty() {
                    Some((0, item.clone()))
                } else {
                    let haystack = format!(
                        "{} {} {} {}",
                        item.header.title,
                        item.header.identity,
                        item.header.url_or_host,
                        item.header.tags.join(" ")
                    );
                    matcher
                        .fuzzy_match(&haystack, query)
                        .map(|score| (score, item.clone()))
                }
            })
            .collect();

        if !query.is_empty() {
            scored.sort_by_key(|a| std::cmp::Reverse(a.0));
        }

        self.filtered_items = scored.into_iter().map(|(_, item)| item).collect();
        if self.filtered_items.is_empty() {
            self.table_state.select(None);
            self.inspected_secret = None;
            self.live_totp = None;
        } else {
            let current = self.table_state.selected().unwrap_or(0);
            let clamped = current.min(self.filtered_items.len() - 1);
            self.table_state.select(Some(clamped));
            self.sync_inspector_state();
        }
    }

    /// Decrypts the Tier-2 secret ONLY when the user explicitly toggles reveal (`r`) or when the item has TOTP.
    pub fn sync_inspector_state(&mut self) {
        let Some(selected) = self.selected_item().cloned() else {
            self.inspected_secret = None;
            self.live_totp = None;
            return;
        };

        if self.reveal_secret || selected.header.has_totp {
            if let Ok(sec) = self.db.decrypt_secret(&self.keys, &selected.id) {
                if let Some(totp_seed) = &sec.totp_secret {
                    self.live_totp = generate_totp_now(totp_seed).ok();
                } else {
                    self.live_totp = None;
                }
                if self.reveal_secret {
                    self.inspected_secret = Some((selected.id, sec));
                } else {
                    self.inspected_secret = None;
                }
            }
        } else {
            self.inspected_secret = None;
            self.live_totp = None;
        }
    }

    pub fn refresh_totp_and_queue(&mut self) {
        if self.local_queue.check_expired() {
            if !self.headless_clipboard {
                let _ = scrub_clipboard();
            }
            self.status_toast = "TTL expired — OS clipboard automatically scrubbed.".to_string();
        }
        self.queue_snapshot = self.local_queue.status();
        self.sync_inspector_state();
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) {
        // Global Ctrl+Shift+V (or Ctrl+N / 'n') advances the sequential clipboard queue
        if (key.modifiers.contains(KeyModifiers::CONTROL)
            && key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V')))
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('n'))
        {
            self.advance_clipboard_queue();
            return;
        }

        match self.mode {
            InputMode::Normal => self.handle_normal_key(key),
            InputMode::Search => self.handle_search_key(key),
            InputMode::AddModal => self.handle_add_modal_key(key),
            InputMode::ConfirmDelete => self.handle_confirm_delete_key(key),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.running = false;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.filtered_items.is_empty() {
                    let next = match self.table_state.selected() {
                        Some(i) => (i + 1) % self.filtered_items.len(),
                        None => 0,
                    };
                    self.table_state.select(Some(next));
                    self.reveal_secret = false;
                    self.sync_inspector_state();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.filtered_items.is_empty() {
                    let prev = match self.table_state.selected() {
                        Some(0) | None => self.filtered_items.len() - 1,
                        Some(i) => i - 1,
                    };
                    self.table_state.select(Some(prev));
                    self.reveal_secret = false;
                    self.sync_inspector_state();
                }
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                let len = CategoryFilter::all_filters().len();
                self.category_filter_idx = (self.category_filter_idx + 1) % len;
                self.recompute_filter();
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                let len = CategoryFilter::all_filters().len();
                self.category_filter_idx = (self.category_filter_idx + len - 1) % len;
                self.recompute_filter();
            }
            KeyCode::Char('/') => {
                self.mode = InputMode::Search;
                self.status_toast =
                    "Fuzzy Search active — type to filter, Enter/Esc to lock.".to_string();
            }
            KeyCode::Char('r') => {
                self.reveal_secret = !self.reveal_secret;
                self.sync_inspector_state();
                self.status_toast = if self.reveal_secret {
                    "Tier-2 Secret decrypted in Zeroizing view buffer.".to_string()
                } else {
                    "Tier-2 Secret masked & zeroized from view buffer.".to_string()
                };
            }
            KeyCode::Enter => {
                self.enqueue_selected_full_sequence();
            }
            KeyCode::Char('n') => {
                self.advance_clipboard_queue();
            }
            KeyCode::Char('y') => {
                self.copy_selected_single(QueueStageKind::PrimarySecret);
            }
            KeyCode::Char('u') => {
                self.copy_selected_single(QueueStageKind::Identity);
            }
            KeyCode::Char('t') => {
                self.copy_selected_single(QueueStageKind::TotpCode);
            }
            KeyCode::Char('x') => {
                self.local_queue.clear();
                if !self.headless_clipboard {
                    let _ = scrub_clipboard();
                }
                self.queue_snapshot = self.local_queue.status();
                self.status_toast = "Clipboard immediately scrubbed clean.".to_string();
            }
            KeyCode::Char('a') => {
                self.draft_form = DraftEntryForm::default();
                self.mode = InputMode::AddModal;
                self.status_toast =
                    "Add New Credential — Tab: Next Field | Enter: Save | Esc: Cancel".to_string();
            }
            KeyCode::Char('d') if self.selected_item().is_some() => {
                self.mode = InputMode::ConfirmDelete;
            }
            _ => {}
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.mode = InputMode::Normal;
                self.status_toast = format!(
                    "Filter locked ({} matches). Press Enter to queue, '/' to edit search.",
                    self.filtered_items.len()
                );
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.recompute_filter();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
                self.recompute_filter();
            }
            _ => {}
        }
    }

    fn handle_add_modal_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.mode = InputMode::Normal;
                self.status_toast = "Cancelled new credential entry.".to_string();
            }
            KeyCode::Tab | KeyCode::Down => {
                self.draft_form.active_field = self.draft_form.active_field.next();
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.draft_form.active_field = self.draft_form.active_field.prev();
            }
            KeyCode::Enter => {
                if self.draft_form.title.trim().is_empty() {
                    self.status_toast = "Title is required before saving.".to_string();
                    return;
                }
                let tags: Vec<String> = self
                    .draft_form
                    .tags_csv
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let totp_opt = if self.draft_form.totp_secret.trim().is_empty() {
                    None
                } else {
                    Some(self.draft_form.totp_secret.trim().to_string())
                };
                let header = Tier1Header {
                    title: self.draft_form.title.trim().to_string(),
                    category: self.draft_form.selected_category(),
                    identity: self.draft_form.identity.trim().to_string(),
                    url_or_host: self.draft_form.url_or_host.trim().to_string(),
                    tags,
                    has_totp: totp_opt.is_some(),
                };
                let secret = Tier2Secret {
                    primary_secret: self.draft_form.primary_secret.clone(),
                    totp_secret: totp_opt,
                    notes: self.draft_form.notes.clone(),
                };

                if let Ok(_id) = self.db.add_entry(&self.keys, header, &secret) {
                    if let Ok(items) = self.db.list_catalogue(&self.keys) {
                        self.all_items = items;
                    }
                    self.mode = InputMode::Normal;
                    self.recompute_filter();
                    self.status_toast =
                        "Saved & sealed new credential in Two-Tier AEAD vault.".to_string();
                }
            }
            KeyCode::Left if self.draft_form.active_field == ModalField::Category => {
                let len = SecretCategory::all().len();
                self.draft_form.category_idx = (self.draft_form.category_idx + len - 1) % len;
            }
            KeyCode::Right if self.draft_form.active_field == ModalField::Category => {
                let len = SecretCategory::all().len();
                self.draft_form.category_idx = (self.draft_form.category_idx + 1) % len;
            }
            KeyCode::Backspace => {
                self.active_draft_string_mut().pop();
            }
            KeyCode::Char(c) => {
                if self.draft_form.active_field == ModalField::Category {
                    let len = SecretCategory::all().len();
                    self.draft_form.category_idx = (self.draft_form.category_idx + 1) % len;
                } else {
                    self.active_draft_string_mut().push(c);
                }
            }
            _ => {}
        }
    }

    fn active_draft_string_mut(&mut self) -> &mut String {
        match self.draft_form.active_field {
            ModalField::Title => &mut self.draft_form.title,
            ModalField::Category => &mut self.draft_form.title,
            ModalField::Identity => &mut self.draft_form.identity,
            ModalField::UrlOrHost => &mut self.draft_form.url_or_host,
            ModalField::Tags => &mut self.draft_form.tags_csv,
            ModalField::PrimarySecret => &mut self.draft_form.primary_secret,
            ModalField::TotpSecret => &mut self.draft_form.totp_secret,
            ModalField::Notes => &mut self.draft_form.notes,
        }
    }

    fn handle_confirm_delete_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some(item) = self.selected_item().cloned()
                    && self.db.delete_entry(&item.id).is_ok()
                {
                    if let Ok(items) = self.db.list_catalogue(&self.keys) {
                        self.all_items = items;
                    }
                    self.recompute_filter();
                    self.status_toast =
                        format!("Deleted `{}` and securely zeroed pages.", item.header.title);
                }
                self.mode = InputMode::Normal;
            }
            _ => {
                self.mode = InputMode::Normal;
                self.status_toast = "Deletion cancelled.".to_string();
            }
        }
    }

    fn enqueue_selected_full_sequence(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };
        let Ok(sec) = self.db.decrypt_secret(&self.keys, &item.id) else {
            return;
        };
        if let Some((kind, payload)) = self.local_queue.load_credential(&item.header, &sec) {
            if !self.headless_clipboard {
                let _ = write_secret_to_clipboard(&payload);
            }
            self.queue_snapshot = self.local_queue.status();
            self.status_toast = format!(
                "Queued `{}` -> {} now on clipboard. Press Ctrl+Shift+V (or 'n') for next stage.",
                item.header.title,
                kind.label()
            );
        }
    }

    fn advance_clipboard_queue(&mut self) {
        if !self.local_queue.is_active() {
            self.status_toast = "No active sequential paste queue.".to_string();
            return;
        }
        if let Some((kind, payload)) = self.local_queue.advance() {
            if !self.headless_clipboard {
                let _ = write_secret_to_clipboard(&payload);
            }
            self.queue_snapshot = self.local_queue.status();
            self.status_toast = format!("Advanced Queue -> {} now on clipboard.", kind.label());
        } else {
            if !self.headless_clipboard {
                let _ = scrub_clipboard();
            }
            self.queue_snapshot = self.local_queue.status();
            self.status_toast =
                "Sequential paste queue complete — OS clipboard scrubbed clean.".to_string();
        }
    }

    fn copy_selected_single(&mut self, kind: QueueStageKind) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };
        let Ok(sec) = self.db.decrypt_secret(&self.keys, &item.id) else {
            return;
        };

        let (val, is_totp) = match kind {
            QueueStageKind::Identity => (item.header.identity.clone(), false),
            QueueStageKind::PrimarySecret => (sec.primary_secret.clone(), false),
            QueueStageKind::TotpCode => match &sec.totp_secret {
                Some(seed) if !seed.trim().is_empty() => (seed.clone(), true),
                _ => {
                    self.status_toast = "Selected entry has no TOTP seed configured.".to_string();
                    return;
                }
            },
        };

        if let Some((k, payload)) =
            self.local_queue
                .load_single_step(&item.header.title, kind, val, is_totp)
        {
            if !self.headless_clipboard {
                let _ = write_secret_to_clipboard(&payload);
            }
            self.queue_snapshot = self.local_queue.status();
            self.status_toast = format!(
                "Copied {} for `{}` (20s auto-scrub).",
                k.label(),
                item.header.title
            );
        }
    }
}
