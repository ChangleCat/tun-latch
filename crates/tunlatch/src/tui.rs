use std::io::IsTerminal;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListState, Paragraph, Wrap};
use tunlatch_core::status::Status;
use tunlatch_ipc::query_status;

pub async fn run(runtime_dir: &Path) -> anyhow::Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("TUI requires an interactive terminal; use the status command for scripts");
    }
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            ratatui::restore();
            return Err(error).context("cannot initialize terminal");
        }
    };
    let result = event_loop(&mut terminal, runtime_dir).await;
    let restored = ratatui::try_restore().context("cannot restore terminal");
    result.and(restored)
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let mut events = EventStream::new();
    let mut refresh = tokio::time::interval(Duration::from_secs(2));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut status = None;
    let mut selection = ListState::default();
    let mut error = Some(String::from("Connecting; protection is unknown"));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Keep one bounded request in flight so a slow service cannot block keyboard input or shutdown.
    let mut pending = Box::pin(query_status(runtime_dir));
    let mut requesting = true;
    loop {
        terminal.draw(|frame| draw(frame, status.as_ref(), error.as_deref(), &mut selection))?;
        tokio::select! {
            result = &mut pending, if requesting => {
                requesting = false;
                match result {
                    Ok(current) => {
                        let index = selection.selected().unwrap_or(0)
                            .min(current.interfaces.len().saturating_sub(1));
                        selection.select(if current.interfaces.is_empty() { None } else { Some(index) });
                        status = Some(current);
                        error = None;
                    }
                    Err(failure) => {
                        status = None;
                        selection.select(None);
                        error = Some(failure.to_string());
                    }
                }
            }
            _tick = refresh.tick() => {
                if !requesting {
                    pending = Box::pin(query_status(runtime_dir));
                    requesting = true;
                }
            }
            _signal = terminate.recv() => return Ok(()),
            signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); }
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc
                        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)) {
                        return Ok(());
                    }
                    if key.code == KeyCode::Char('r') && !requesting {
                        pending = Box::pin(query_status(runtime_dir));
                        requesting = true;
                    }
                    if let Some(current) = &status {
                        let index = selection.selected().unwrap_or(0);
                        let last = current.interfaces.len().saturating_sub(1);
                        let next = match key.code {
                            KeyCode::Down | KeyCode::Char('j') => index.saturating_add(1).min(last),
                            KeyCode::Up | KeyCode::Char('k') => index.saturating_sub(1),
                            KeyCode::PageDown => index.saturating_add(10).min(last),
                            KeyCode::PageUp => index.saturating_sub(10),
                            _ => index,
                        };
                        if !current.interfaces.is_empty() { selection.select(Some(next)); }
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error.into()),
                None => bail!("terminal input closed"),
            }
        }
    }
}

fn draw(
    frame: &mut Frame<'_>,
    status: Option<&Status>,
    error: Option<&str>,
    selection: &mut ListState,
) {
    let areas = Layout::vertical([
        Constraint::Length(6),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(frame.area());
    let mut summary = vec![
        Line::from("Protection: UNKNOWN — PF backend not implemented".fg(Color::Yellow)),
        Line::from("Read-only framework; no firewall policy has been applied."),
    ];
    if let Some(status) = status {
        summary.push(Line::from(format!(
            "Desired: {:?} | Committed: {:?} | Trusted TUN: none",
            status.desired, status.committed
        )));
    }
    if let Some(error) = error {
        summary.push(Line::from(format!("Service unavailable: {error}")).fg(Color::Red));
    }
    frame.render_widget(
        Paragraph::new(summary)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("TunLatch / development observer")),
        areas[0],
    );
    let interfaces = status
        .map(|status| {
            status
                .interfaces
                .iter()
                .filter(|interface| interface.is_tun_candidate())
                .chain(
                    status
                        .interfaces
                        .iter()
                        .filter(|interface| !interface.is_tun_candidate()),
                )
                .map(|interface| {
                    let hint = if interface.is_tun_candidate() {
                        "candidate, untrusted"
                    } else {
                        "interface"
                    };
                    let addresses = interface
                        .addresses
                        .iter()
                        .map(|address| {
                            if address.scope_id == 0 {
                                address.address.to_string()
                            } else {
                                format!("{}%{}", address.address, address.scope_id)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Line::from(format!(
                        "{} #{} [{hint}] {}",
                        interface.name, interface.index, addresses
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    frame.render_stateful_widget(
        List::new(interfaces)
            .highlight_style(Style::new().bg(Color::DarkGray))
            .highlight_symbol("> ")
            .block(Block::bordered().title("IPv4 / IPv6 discovery — candidates first (untrusted)")),
        areas[1],
        selection,
    );
    frame.render_widget(Paragraph::new("q / Esc: quit   r: refresh   ↑/↓ j/k PgUp/PgDn: browse   refresh: 2s\nQuitting the UI does not change firewall state."), areas[2]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn disconnected_dashboard_displays_unknown_and_no_stale_interfaces() -> anyhow::Result<()> {
        let mut terminal = Terminal::new(TestBackend::new(100, 20))?;
        terminal.draw(|frame| {
            draw(
                frame,
                None,
                Some("connection closed"),
                &mut ListState::default(),
            )
        })?;
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("Protection: UNKNOWN"));
        assert!(text.contains("connection closed"));
        assert!(!text.contains("candidate, untrusted"));
        Ok(())
    }

    #[test]
    fn tiny_terminal_does_not_panic() -> anyhow::Result<()> {
        let mut terminal = Terminal::new(TestBackend::new(1, 1))?;
        terminal.draw(|frame| draw(frame, None, None, &mut ListState::default()))?;
        Ok(())
    }

    #[test]
    fn candidates_are_visible_and_full_interface_list_can_scroll() -> anyhow::Result<()> {
        use tunlatch_core::status::{
            CommittedPolicy, NetworkInterface, ObservedProtection, UnknownReason,
        };
        let mut interfaces = (0..25)
            .map(|index| NetworkInterface {
                name: format!("en{index:02}"),
                index,
                up: true,
                loopback: false,
                addresses: Vec::new(),
            })
            .collect::<Vec<_>>();
        interfaces.push(NetworkInterface {
            name: "utun7".into(),
            index: 30,
            up: true,
            loopback: false,
            addresses: Vec::new(),
        });
        let status = Status {
            desired: Default::default(),
            committed: CommittedPolicy::Unmanaged,
            observed: ObservedProtection::Unknown {
                reason: UnknownReason::BackendNotImplemented,
            },
            interfaces,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24))?;
        let mut selection = ListState::default().with_selected(Some(0));
        terminal.draw(|frame| draw(frame, Some(&status), None, &mut selection))?;
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("utun7"));
        assert!(text.contains("candidate, untrusted"));
        selection.select(Some(25));
        terminal.draw(|frame| draw(frame, Some(&status), None, &mut selection))?;
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("en24"));
        assert!(selection.offset() > 0);
        Ok(())
    }
}
