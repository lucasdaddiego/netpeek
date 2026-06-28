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

    /// Handle one command. `len` is the number of currently-visible rows and
    /// `selected_pid` the pid under the cursor (for expand), both supplied by the
    /// render loop from the freshly filtered+sorted list.
    pub fn handle(&mut self, cmd: Cmd, len: usize, selected_pid: Option<u32>) {
        // While typing a filter, most keys edit the query.
        if self.mode == Mode::Filter {
            match cmd {
                Cmd::FilterChar(c) => self.filter.push(c),
                Cmd::FilterBackspace => {
                    self.filter.pop();
                }
                Cmd::FilterAccept => self.mode = Mode::Normal,
                Cmd::FilterCancel => {
                    self.filter.clear();
                    self.mode = Mode::Normal;
                }
                Cmd::Quit => self.mode = Mode::Normal,
                _ => {}
            }
            self.clamp_selection(len);
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
        self.clamp_selection(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_clamps() {
        let mut a = App::default();
        a.handle(Cmd::Down, 3, None);
        assert_eq!(a.selected, 1);
        a.handle(Cmd::Up, 3, None);
        assert_eq!(a.selected, 0);
        a.handle(Cmd::Up, 3, None); // already at top
        assert_eq!(a.selected, 0);
        a.handle(Cmd::End, 3, None);
        assert_eq!(a.selected, 2);
        a.handle(Cmd::Down, 3, None); // at bottom
        assert_eq!(a.selected, 2);
        a.handle(Cmd::Home, 3, None);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn paging_and_empty_list() {
        let mut a = App {
            page: 5,
            ..App::default()
        };
        a.handle(Cmd::PageDown, 20, None);
        assert_eq!(a.selected, 5);
        a.handle(Cmd::PageDown, 20, None);
        assert_eq!(a.selected, 10);
        a.handle(Cmd::PageUp, 20, None);
        assert_eq!(a.selected, 5);
        // empty list keeps selection at 0
        a.handle(Cmd::Down, 0, None);
        a.handle(Cmd::PageDown, 0, None);
        a.handle(Cmd::End, 0, None);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn selection_clamps_when_list_shrinks() {
        let mut a = App::default();
        a.handle(Cmd::End, 10, None);
        assert_eq!(a.selected, 9);
        a.handle(Cmd::Up, 3, None); // list shrank to 3
        assert!(a.selected < 3);
    }

    #[test]
    fn sort_toggles_direction_on_repeat() {
        let mut a = App::default();
        assert_eq!(a.sort, SortKey::Rate);
        assert!(a.sort_desc);
        a.handle(Cmd::Sort(SortKey::Rate), 0, None); // same key flips
        assert!(!a.sort_desc);
        a.handle(Cmd::Sort(SortKey::Name), 0, None); // new key: ascending default
        assert_eq!(a.sort, SortKey::Name);
        assert!(!a.sort_desc);
        a.handle(Cmd::Sort(SortKey::Total), 0, None); // numeric: descending default
        assert!(a.sort_desc);
    }

    #[test]
    fn expand_toggles_on_selected_pid() {
        let mut a = App::default();
        a.handle(Cmd::ToggleExpand, 3, Some(42));
        assert_eq!(a.expanded, Some(42));
        a.handle(Cmd::ToggleExpand, 3, Some(42)); // same → collapse
        assert_eq!(a.expanded, None);
        a.handle(Cmd::ToggleExpand, 3, Some(7));
        assert_eq!(a.expanded, Some(7));
        a.handle(Cmd::ToggleExpand, 3, Some(8)); // different → switch
        assert_eq!(a.expanded, Some(8));
    }

    #[test]
    fn pause_and_help_toggle() {
        let mut a = App::default();
        a.handle(Cmd::Pause, 0, None);
        assert!(a.paused);
        a.handle(Cmd::Pause, 0, None);
        assert!(!a.paused);
        a.handle(Cmd::Help, 0, None);
        assert!(a.show_help);
        // q closes help rather than quitting
        a.handle(Cmd::Quit, 0, None);
        assert!(!a.show_help);
        assert!(!a.should_quit);
        // q again quits
        a.handle(Cmd::Quit, 0, None);
        assert!(a.should_quit);
    }

    #[test]
    fn filter_mode_editing() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, 5, None);
        assert_eq!(a.mode, Mode::Filter);
        a.handle(Cmd::FilterChar('f'), 5, None);
        a.handle(Cmd::FilterChar('o'), 5, None);
        a.handle(Cmd::FilterChar('x'), 5, None);
        assert_eq!(a.filter, "fox");
        a.handle(Cmd::FilterBackspace, 5, None);
        assert_eq!(a.filter, "fo");
        a.handle(Cmd::FilterAccept, 5, None);
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.filter, "fo"); // kept
                                    // navigation commands don't edit the (now normal-mode) filter
        a.handle(Cmd::Down, 5, None);
        assert_eq!(a.filter, "fo");
    }

    #[test]
    fn filter_cancel_clears() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, 5, None);
        a.handle(Cmd::FilterChar('z'), 5, None);
        a.handle(Cmd::FilterCancel, 5, None);
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.filter.is_empty());
    }

    #[test]
    fn quit_in_filter_mode_just_exits_filter() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, 5, None);
        a.handle(Cmd::Quit, 5, None);
        assert_eq!(a.mode, Mode::Normal);
        assert!(!a.should_quit);
    }

    #[test]
    fn filter_mode_ignores_navigation_commands() {
        let mut a = App::default();
        a.handle(Cmd::FilterStart, 5, None);
        a.handle(Cmd::FilterChar('a'), 5, None);
        // a navigation command in filter mode is a no-op (doesn't move/quit)
        a.handle(Cmd::Down, 5, None);
        a.handle(Cmd::Sort(SortKey::Name), 5, None);
        assert_eq!(a.mode, Mode::Filter);
        assert_eq!(a.selected, 0);
        assert_eq!(a.filter, "a");
    }

    #[test]
    fn normal_mode_ignores_filter_edit_commands() {
        let mut a = App::default();
        a.handle(Cmd::FilterChar('x'), 5, None);
        a.handle(Cmd::FilterBackspace, 5, None);
        a.handle(Cmd::FilterAccept, 5, None);
        a.handle(Cmd::FilterCancel, 5, None);
        assert!(a.filter.is_empty());
        assert_eq!(a.mode, Mode::Normal);
    }
}
