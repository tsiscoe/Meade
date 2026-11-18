use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::importer::sanitize_terminal_str;
use crate::tui::app::{CategoryFilter, InputMode, ModalField, TuiApp};

const ACCENT_RED: Color = Color::Rgb(236, 48, 19); // #ec3013 Modernist Accent Red
const MUTED_GRAY: Color = Color::Rgb(158, 154, 152);
const SURFACE_BG: Color = Color::Rgb(18, 19, 22);
const ACTIVE_GREEN: Color = Color::Rgb(76, 209, 55);

/// Renders the complete Meade Multi-Pane Catalogue Viewer into a Ratatui Frame.
pub fn render_tui(app: &mut TuiApp, frame: &mut Frame) {
    let area = frame.area();
    if area.width < 25 || area.height < 8 {
        let fallback = Paragraph::new("Meade TUI: Expand terminal viewport (>= 40x12)")
            .style(Style::default().fg(ACCENT_RED));
        frame.render_widget(fallback, area);
        return;
    }

    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top Masthead + Fuzzy Search Bar
            Constraint::Min(5),    // Main 3-Pane Body (Sidebar + Catalogue Table + Inspector)
            Constraint::Length(4), // Bottom Sequential Clipboard Queue & Hotkey Footer
        ])
        .split(area);

    render_header_and_search(app, frame, root_chunks[0]);
    render_main_panes(app, frame, root_chunks[1]);
    render_queue_footer(app, frame, root_chunks[2]);

    match app.mode {
        InputMode::AddModal => render_add_modal(app, frame, area),
        InputMode::ConfirmDelete => render_confirm_delete_modal(app, frame, area),
        _ => {}
    }
}

fn render_header_and_search(app: &TuiApp, frame: &mut Frame, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let title_line = Line::from(vec![
        Span::styled(
            " [MEADE // VAULT] ",
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        ),
        Span::raw("Two-Tier XChaCha20-Poly1305 "),
        Span::styled(
            format!("({} items)", app.filtered_items.len()),
            Style::default().fg(MUTED_GRAY),
        ),
    ]);
    let brand_block = Paragraph::new(title_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(MUTED_GRAY)),
    );
    frame.render_widget(brand_block, cols[0]);

    let search_border_color = if app.mode == InputMode::Search {
        ACCENT_RED
    } else {
        MUTED_GRAY
    };
    let search_prefix = if app.mode == InputMode::Search {
        " [SEARCHING] / "
    } else {
        " [Press / to Fuzzy Filter] "
    };
    let search_text = Line::from(vec![
        Span::styled(
            search_prefix,
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        ),
        Span::raw(&app.search_query),
    ]);
    let search_box = Paragraph::new(search_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(search_border_color)),
    );
    frame.render_widget(search_box, cols[1]);
}

fn render_main_panes(app: &mut TuiApp, frame: &mut Frame, area: Rect) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24),     // Category Filter Sidebar
            Constraint::Percentage(52), // Catalogue Table
            Constraint::Min(24),        // Cryptographic Inspector & Live TOTP
        ])
        .split(area);

    render_category_sidebar(app, frame, panes[0]);
    render_catalogue_table(app, frame, panes[1]);
    render_inspector_pane(app, frame, panes[2]);
}

fn render_category_sidebar(app: &TuiApp, frame: &mut Frame, area: Rect) {
    let filters = CategoryFilter::all_filters();
    let items: Vec<ListItem> = filters
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let selected = idx == app.category_filter_idx;
            let prefix = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::styled(format!("{prefix}{}", f.label()), style))
        })
        .collect();

    let sidebar = List::new(items).block(
        Block::default()
            .title(Span::styled(
                " [CATEGORIES (Tab)] ",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(MUTED_GRAY)),
    );
    frame.render_widget(sidebar, area);
}

fn render_catalogue_table(app: &mut TuiApp, frame: &mut Frame, area: Rect) {
    if app.filtered_items.is_empty() {
        let empty = Paragraph::new(vec![
            Line::raw(""),
            Line::styled(
                "  No matching credentials in this view.",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "  Press 'a' to add a new secret, or '/' to clear your search filter.",
                Style::default().fg(MUTED_GRAY),
            ),
        ])
        .block(
            Block::default()
                .title(Span::styled(
                    " [CATALOGUE] ",
                    Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        );
        frame.render_widget(empty, area);
        return;
    }

    let header_cells = ["Type", "Title", "Identity / Host", "Tags"]
        .into_iter()
        .map(|h| Cell::from(h).style(Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows = app.filtered_items.iter().map(|item| {
        let badge = item.header.category.short_badge();
        let tags_str = item
            .header
            .tags
            .iter()
            .map(|t| format!("[{}]", sanitize_terminal_str(t, false)))
            .collect::<Vec<_>>()
            .join(" ");
        Row::new(vec![
            Cell::from(badge).style(Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD)),
            Cell::from(sanitize_terminal_str(&item.header.title, false)),
            Cell::from(sanitize_terminal_str(&item.header.identity, false))
                .style(Style::default().fg(MUTED_GRAY)),
            Cell::from(tags_str).style(Style::default().fg(ACCENT_RED)),
        ])
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Percentage(38),
        Constraint::Percentage(32),
        Constraint::Percentage(22),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(Span::styled(
                    " [CATALOGUE // TIER-1 HEADERS] ",
                    Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MUTED_GRAY)),
        )
        .row_highlight_style(
            Style::default()
                .bg(SURFACE_BG)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_inspector_pane(app: &TuiApp, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(Span::styled(
            " [INSPECTOR // TIER-2 ENVELOPE] ",
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED_GRAY));

    let Some(item) = app.selected_item() else {
        let p = Paragraph::new("Select an entry to inspect metadata or dispatch to clipboard.")
            .style(Style::default().fg(MUTED_GRAY))
            .block(block);
        frame.render_widget(p, area);
        return;
    };

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // Metadata & Secret status
            Constraint::Length(3), // Live TOTP Gauge
        ])
        .split(inner);

    let secret_display = if app.reveal_secret {
        app.inspected_secret
            .as_ref()
            .map(|(_, s)| s.primary_secret.as_str())
            .unwrap_or("<empty>")
    } else {
        "•••••••••••••••••••••••• [Sealed in Tier-2 XChaCha20 — Press 'r' to reveal]"
    };

    let notes_display = if app.reveal_secret {
        app.inspected_secret
            .as_ref()
            .map(|(_, s)| s.notes.as_str())
            .unwrap_or("")
    } else {
        "[Encrypted until revealed or queued]"
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("Title:    ", Style::default().fg(MUTED_GRAY)),
            Span::styled(
                &item.header.title,
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Category: ", Style::default().fg(MUTED_GRAY)),
            Span::styled(
                item.header.category.short_badge(),
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {}", item.header.category.label())),
        ]),
        Line::from(vec![
            Span::styled("Identity: ", Style::default().fg(MUTED_GRAY)),
            Span::raw(&item.header.identity),
        ]),
        Line::from(vec![
            Span::styled("Host/URL: ", Style::default().fg(MUTED_GRAY)),
            Span::raw(&item.header.url_or_host),
        ]),
        Line::from(vec![
            Span::styled("Secret:   ", Style::default().fg(MUTED_GRAY)),
            Span::styled(
                secret_display,
                if app.reveal_secret {
                    Style::default()
                        .fg(ACTIVE_GREEN)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(MUTED_GRAY)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("Notes:    ", Style::default().fg(MUTED_GRAY)),
            Span::raw(notes_display),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                "[Enter]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Queue Sequence  "),
            Span::styled(
                "[y]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Copy Secret  "),
            Span::styled(
                "[u]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Copy User  "),
            Span::styled(
                "[t]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Copy TOTP"),
        ]),
    ];

    let details = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(details, chunks[0]);

    if let Some(totp) = &app.live_totp {
        let ratio = (totp.remaining_secs as f64 / totp.period_secs as f64).clamp(0.0, 1.0);
        let label = format!(
            "RFC 6238 TOTP: {} ({}s remaining)",
            totp.code, totp.remaining_secs
        );
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::TOP).title(" [LIVE 2FA] "))
            .gauge_style(Style::default().fg(ACCENT_RED).bg(SURFACE_BG))
            .ratio(ratio)
            .label(Span::styled(
                label,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
        frame.render_widget(gauge, chunks[1]);
    } else {
        let no_totp = Paragraph::new("No RFC 6238 TOTP configured for this entry.")
            .style(Style::default().fg(MUTED_GRAY))
            .block(Block::default().borders(Borders::TOP).title(" [LIVE 2FA] "));
        frame.render_widget(no_totp, chunks[1]);
    }
}

fn render_queue_footer(app: &TuiApp, frame: &mut Frame, area: Rect) {
    let q = &app.queue_snapshot;
    let queue_line = if q.active {
        Line::from(vec![
            Span::styled(
                " [ACTIVE QUEUE] ",
                Style::default()
                    .fg(ACTIVE_GREEN)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                &q.entry_title,
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " — [{}/{}] {} ",
                q.current_stage_index, q.total_stages, q.current_stage_label
            )),
            Span::styled(
                format!("[Auto-Scrub: {}s]", q.remaining_ttl_secs),
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  Press "),
            Span::styled(
                "[Ctrl+Shift+V]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" or "),
            Span::styled(
                "[n]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to Advance  |  "),
            Span::styled(
                "[x]",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Scrub Now"),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                " [CLIPBOARD IDLE] ",
                Style::default().fg(MUTED_GRAY).add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                "Win32 Cloud/History Exclusion Active  |  [Enter] Queue Sequence  [a] Add  [d] Delete  [r] Reveal  [q] Quit",
            ),
        ])
    };

    let toast_line = Line::from(vec![
        Span::styled(
            " [STATUS] ",
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        ),
        Span::raw(&app.status_toast),
    ]);

    let footer = Paragraph::new(vec![queue_line, toast_line]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(MUTED_GRAY)),
    );
    frame.render_widget(footer, area);
}

fn render_add_modal(app: &TuiApp, frame: &mut Frame, area: Rect) {
    let popup = centered_rect(70, 75, area);
    frame.render_widget(Clear, popup);

    let f = &app.draft_form;
    let field_line = |field: ModalField, label: &str, val: &str| -> Line {
        let active = f.active_field == field;
        let prefix = if active { "▶ " } else { "  " };
        let style = if active {
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED_GRAY)
        };
        Line::from(vec![
            Span::styled(format!("{prefix}{label:<16}"), style),
            Span::styled(val.to_string(), Style::default().fg(Color::White)),
        ])
    };

    let lines = vec![
        field_line(ModalField::Title, "Title:", &f.title),
        field_line(
            ModalField::Category,
            "Category (←/→):",
            f.selected_category().label(),
        ),
        field_line(ModalField::Identity, "Identity/User:", &f.identity),
        field_line(ModalField::UrlOrHost, "URL / Host:", &f.url_or_host),
        field_line(ModalField::Tags, "Tags (CSV):", &f.tags_csv),
        field_line(
            ModalField::PrimarySecret,
            "Primary Secret:",
            &f.primary_secret,
        ),
        field_line(ModalField::TotpSecret, "TOTP Base32:", &f.totp_secret),
        field_line(ModalField::Notes, "Notes:", &f.notes),
        Line::raw(""),
        Line::styled(
            "  [Tab/↑/↓] Navigate Fields   [Enter] Seal & Save   [Esc] Cancel",
            Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
        ),
    ];

    let modal = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                " [ADD CREDENTIAL // TWO-TIER AEAD SEAL] ",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT_RED)),
    );
    frame.render_widget(modal, popup);
}

fn render_confirm_delete_modal(app: &TuiApp, frame: &mut Frame, area: Rect) {
    let popup = centered_rect(50, 25, area);
    frame.render_widget(Clear, popup);
    let title = app
        .selected_item()
        .map(|i| i.header.title.as_str())
        .unwrap_or("selected entry");

    let text = vec![
        Line::raw(""),
        Line::from(vec![
            Span::raw("  Permanently delete "),
            Span::styled(
                title,
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ),
            Span::raw("?"),
        ]),
        Line::raw(""),
        Line::styled(
            "  Press [y] to Confirm Delete, or [n / Esc] to Cancel.",
            Style::default().fg(MUTED_GRAY),
        ),
    ];

    let modal = Paragraph::new(text).block(
        Block::default()
            .title(Span::styled(
                " [CONFIRM SECURE DELETE] ",
                Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT_RED)),
    );
    frame.render_widget(modal, popup);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
