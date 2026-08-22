//! UI state and its transitions — kept free of ratatui/crossterm so the
//! navigation, sorting, filtering and mode logic are unit-tested directly.
//!
//! The render loop translates terminal events into [`Cmd`]s and feeds them to
//! [`App::handle`]; rendering then reads the resulting state.

use crate::model::SortKey;

/// Logical commands the UI understands, decoupled from physical key events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    Quit,
    /// Back out one level: close the help, else clear an applied filter, else
    /// quit — so a stray Esc doesn't drop the user out of the app.
    Escape,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Sort(SortKey),
    ToggleExpand,
    Pause,
    Help,
    /// Enter incremental-filter input mode.
    FilterStart,
    FilterChar(char),
    FilterBackspace,
    /// Confirm the filter and leave input mode (keeps the text).
    FilterAccept,
    /// Leave input mode and clear the filter.
    FilterCancel,
}

/// Whether the UI is in normal navigation or typing a filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Filter,
}

pub struct App {
    pub sort: SortKey,
    pub sort_desc: bool,
    pub filter: String,
    pub mode: Mode,
    pub selected: usize,
    pub expanded: Option<u32>,
    pub paused: bool,
    pub show_help: bool,
    pub should_quit: bool,
    /// Rows shown per page jump — set from the viewport each frame.
    pub page: usize,
    /// Pid under the cursor. Re-found after every rebuild so the selection
    /// follows the *process*, not the row index — a live sort reorders the rows
    /// every tick, and an index-bound highlight would hop between processes.
    pub anchor: Option<u32>,
}

impl Default for App {
    fn default() -> Self {
        App {
            sort: SortKey::Rate,
            sort_desc: true,
            filter: String::new(),
            mode: Mode::Normal,
            selected: 0,
            expanded: None,
            paused: false,
            show_help: false,
            should_quit: false,
            page: 10,
            anchor: None,
        }
    }
}

impl App {
    /// Default sort direction for a freshly-chosen column: descending for the
    /// numeric "biggest first" columns, ascending for name/pid.
    fn default_desc(key: SortKey) -> bool {
        matches!(key, SortKey::Rate | SortKey::Total | SortKey::Conns)
    }

    /// Choose a sort column, or flip direction if it's already selected.
    fn apply_sort(&mut self, key: SortKey) {
        if self.sort == key {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort = key;
            self.sort_desc = Self::default_desc(key);
        }
    }

    /// Keep `selected` within `[0, len)` (clamps to 0 when empty).
    pub fn clamp_selection(&mut self, len: usize) {
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Re-aim the cursor after the visible rows were rebuilt: if the anchored
    /// pid is still shown, follow it to its new index; otherwise keep the index,
    /// clamped. Then re-anchor to whatever is now under the cursor. `pids` is
    /// the freshly filtered+sorted list, top to bottom.
    pub fn sync_selection(&mut self, pids: &[u32]) {
        if let Some(p) = self.anchor
            && let Some(i) = pids.iter().position(|&x| x == p)
        {
            self.selected = i;
        }
        self.clamp_selection(pids.len());
        self.anchor = pids.get(self.selected).copied();
    }

    /// Handle one command against `pids`, the pids of the currently-visible rows
    /// in display order (the render loop supplies it from the last frame). The
    /// cursor is re-anchored to the row it lands on.
    pub fn handle(&mut self, cmd: Cmd, pids: &[u32]) {
        let len = pids.len();
        // While typing a filter, most keys edit the query.
        if self.mode == Mode::Filter {
            match cmd {
                Cmd::FilterChar(c) => self.filter.push(c),
                Cmd::FilterBackspace => {
                    self.filter.pop();
                }
                Cmd::FilterAccept => self.mode = Mode::Normal,
                Cmd::FilterCancel | Cmd::Escape => {
                    self.filter.clear();
                    self.mode = Mode::Normal;
                }
                Cmd::Quit => self.mode = Mode::Normal,
                _ => {}
            }
            self.sync_selection(pids);
            return;
        }

        match cmd {
            Cmd::Quit => {
                if self.show_help {
                    self.show_help = false;
                } else {
                    self.should_quit = true;
                }
            }
            Cmd::Escape => {
                if self.show_help {
                    self.show_help = false;
                } else if !self.filter.is_empty() {
                    self.filter.clear();
                } else {
                    self.should_quit = true;
                }
            }
            Cmd::Up => self.selected = self.selected.saturating_sub(1),
            Cmd::Down => {
                if len > 0 && self.selected + 1 < len {
                    self.selected += 1;
                }
            }
            Cmd::PageUp => self.selected = self.selected.saturating_sub(self.page.max(1)),
            Cmd::PageDown => {
                if len > 0 {
                    self.selected = (self.selected + self.page.max(1)).min(len - 1);
                }
            }
            Cmd::Home => self.selected = 0,
            Cmd::End => self.selected = len.saturating_sub(1),
            Cmd::Sort(k) => self.apply_sort(k),
            Cmd::ToggleExpand => {
                let selected_pid = pids.get(self.selected).copied();
                self.expanded = match (self.expanded, selected_pid) {
                    (Some(p), Some(s)) if p == s => None, // collapse same row
                    (_, sel) => sel,                      // expand current (or none)
                };
            }
            Cmd::Pause => self.paused = !self.paused,
            Cmd::Help => self.show_help = !self.show_help,
            Cmd::FilterStart => self.mode = Mode::Filter,
            // filter-edit commands are inert in normal mode
            Cmd::FilterChar(_) | Cmd::FilterBackspace | Cmd::FilterAccept | Cmd::FilterCancel => {}
        }
        // Navigation moved the index: anchor to the row it now sits on (the
        // list itself hasn't changed, so there's no pid to follow yet).
        self.clamp_selection(len);
        self.anchor = pids.get(self.selected).copied();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` visible rows with pids 0..n.
    fn pids(n: u32) -> Vec<u32> {
        (0..n).collect()
    }

    #[test]
    fn navigation_clamps() {
        let mut a = App::default();
        a.handle(Cmd::Down, &pids(3));
        assert_eq!(a.selected, 1);
        a.handle(Cmd::Up, &pids(3));
        assert_eq!(a.selected, 0);
        a.handle(Cmd::Up, &pids(3)); // already at top
        assert_eq!(a.selected, 0);
        a.handle(Cmd::End, &pids(3));
        assert_eq!(a.selected, 2);
        a.handle(Cmd::Down, &pids(3)); // at bottom
        assert_eq!(a.selected, 2);
        a.handle(Cmd::Home, &pids(3));
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn paging_and_empty_list() {
        let mut a = App {
            page: 5,
            ..App::default()
        };
        a.handle(Cmd::PageDown, &pids(20));
        assert_eq!(a.selected, 5);
        a.handle(Cmd::PageDown, &pids(20));
        assert_eq!(a.selected, 10);
        a.handle(Cmd::PageUp, &pids(20));
        assert_eq!(a.selected, 5);
        // empty list keeps selection at 0
        a.handle(Cmd::Down, &pids(0));
        a.handle(Cmd::PageDown, &pids(0));
        a.handle(Cmd::End, &pids(0));
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn selection_clamps_when_list_shrinks() {
        let mut a = App::default();
        a.handle(Cmd::End, &pids(10));
        assert_eq!(a.selected, 9);
        a.handle(Cmd::Up, &pids(3)); // list shrank to 3
        assert!(a.selected < 3);
    }

    #[test]
    fn sort_toggles_direction_on_repeat() {
        let mut a = App::default();
        assert_eq!(a.sort, SortKey::Rate);
        assert!(a.sort_desc);
        a.handle(Cmd::Sort(SortKey::Rate), &pids(0)); // same key flips
        assert!(!a.sort_desc);
        a.handle(Cmd::Sort(SortKey::Name), &pids(0)); // new key: ascending default
        assert_eq!(a.sort, SortKey::Name);
        assert!(!a.sort_desc);
        a.handle(Cmd::Sort(SortKey::Total), &pids(0)); // numeric: descending default
        assert!(a.sort_desc);
    }

    #[test]
    fn expand_toggles_on_selected_pid() {
        let mut a = App::default();
        a.handle(Cmd::ToggleExpand, &[42, 1, 2]);
        assert_eq!(a.expanded, Some(42));
        a.handle(Cmd::ToggleExpand, &[42, 1, 2]); // same → collapse
        assert_eq!(a.expanded, None);
        a.handle(Cmd::ToggleExpand, &[7, 1, 2]);
        assert_eq!(a.expanded, Some(7));
        a.handle(Cmd::ToggleExpand, &[8, 1, 2]); // different → switch
        assert_eq!(a.expanded, Some(8));
    }

    #[test]
    fn pause_and_help_toggle() {
        let mut a = App::default();
        a.handle(Cmd::Pause, &pids(0));
        assert!(a.paused);
        a.handle(Cmd::Pause, &pids(0));
        assert!(!a.paused);
        a.handle(Cmd::Help, &pids(0));
        assert!(a.show_help);
        // q closes help rather than quitting
        a.handle(Cmd::Quit, &pids(0));
        assert!(!a.show_help);
        assert!(!a.should_quit);
        // q again quits
        a.handle(Cmd::Quit, &pids(0));
        assert!(a.should_quit);
    }

    #[test]
    fn filter_mode_editing() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, &pids(5));
        assert_eq!(a.mode, Mode::Filter);
        a.handle(Cmd::FilterChar('f'), &pids(5));
        a.handle(Cmd::FilterChar('o'), &pids(5));
        a.handle(Cmd::FilterChar('x'), &pids(5));
        assert_eq!(a.filter, "fox");
        a.handle(Cmd::FilterBackspace, &pids(5));
        assert_eq!(a.filter, "fo");
        a.handle(Cmd::FilterAccept, &pids(5));
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.filter, "fo"); // kept
        // navigation commands don't edit the (now normal-mode) filter
        a.handle(Cmd::Down, &pids(5));
        assert_eq!(a.filter, "fo");
    }

    #[test]
    fn filter_cancel_clears() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, &pids(5));
        a.handle(Cmd::FilterChar('z'), &pids(5));
        a.handle(Cmd::FilterCancel, &pids(5));
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.filter.is_empty());
    }

    #[test]
    fn quit_in_filter_mode_just_exits_filter() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, &pids(5));
        a.handle(Cmd::Quit, &pids(5));
        assert_eq!(a.mode, Mode::Normal);
        assert!(!a.should_quit);
    }

    #[test]
    fn filter_mode_ignores_navigation_commands() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, &pids(5));
        a.handle(Cmd::FilterChar('a'), &pids(5));
        // a navigation command in filter mode is a no-op (doesn't move/quit)
        a.handle(Cmd::Down, &pids(5));
        a.handle(Cmd::Sort(SortKey::Name), &pids(5));
        assert_eq!(a.mode, Mode::Filter);
        assert_eq!(a.selected, 0);
        assert_eq!(a.filter, "a");
    }

    #[test]
    fn selection_follows_the_anchored_pid_across_a_resort() {
        let mut a = App::default();
        a.handle(Cmd::Down, &[10, 20, 30]); // cursor on pid 20
        assert_eq!(a.selected, 1);
        assert_eq!(a.anchor, Some(20));
        // the live sort moved pid 20 to the top
        a.sync_selection(&[20, 30, 10]);
        assert_eq!(a.selected, 0);
        assert_eq!(a.anchor, Some(20));
        // the anchored pid vanished: keep the (clamped) index, re-anchor
        a.sync_selection(&[30]);
        assert_eq!(a.selected, 0);
        assert_eq!(a.anchor, Some(30));
        a.sync_selection(&[]);
        assert_eq!(a.selected, 0);
        assert_eq!(a.anchor, None);
    }

    #[test]
    fn escape_backs_out_one_level_at_a_time() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, &pids(5));
        a.handle(Cmd::FilterChar('x'), &pids(5));
        a.handle(Cmd::FilterAccept, &pids(5));
        a.handle(Cmd::Help, &pids(5));
        assert!(a.show_help);
        a.handle(Cmd::Escape, &pids(5)); // 1: closes help
        assert!(!a.show_help);
        assert_eq!(a.filter, "x");
        a.handle(Cmd::Escape, &pids(5)); // 2: clears the applied filter
        assert!(a.filter.is_empty());
        assert!(!a.should_quit);
        a.handle(Cmd::Escape, &pids(5)); // 3: nothing left to back out of
        assert!(a.should_quit);
        // while typing, Esc cancels the filter like FilterCancel
        let mut a = App::default();
        a.handle(Cmd::FilterStart, &pids(5));
        a.handle(Cmd::FilterChar('z'), &pids(5));
        a.handle(Cmd::Escape, &pids(5));
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.filter.is_empty());
        assert!(!a.should_quit);
    }

    #[test]
    fn normal_mode_ignores_filter_edit_commands() {
        let mut a = App::default();
        a.handle(Cmd::FilterChar('x'), &pids(5));
        a.handle(Cmd::FilterBackspace, &pids(5));
        a.handle(Cmd::FilterAccept, &pids(5));
        a.handle(Cmd::FilterCancel, &pids(5));
        assert!(a.filter.is_empty());
        assert_eq!(a.mode, Mode::Normal);
    }
}
