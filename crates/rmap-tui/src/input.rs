//! A single-line text input with a cursor, shared by the setup form and the
//! export dialog.

use std::fmt;
use std::ops::Deref;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Text plus a cursor position, counted in characters (not bytes), so
/// multi-byte input can never split a character or panic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextInput {
    text: String,
    cursor: usize,
}

impl TextInput {
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let cursor = text.chars().count();
        TextInput { text, cursor }
    }

    /// Cursor position in characters from the start.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn len_chars(&self) -> usize {
        self.text.chars().count()
    }

    fn byte_at(&self, char_idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(char_idx)
            .map_or(self.text.len(), |(i, _)| i)
    }

    pub fn insert(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        let at = self.byte_at(self.cursor);
        self.text.insert(at, c);
        self.cursor += 1;
    }

    pub fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.insert(c);
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let at = self.byte_at(self.cursor);
        self.text.remove(at);
    }

    pub fn delete(&mut self) {
        if self.cursor < self.len_chars() {
            let at = self.byte_at(self.cursor);
            self.text.remove(at);
        }
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    /// Ctrl-W: delete back to the start of the previous word. Commas and
    /// whitespace both separate words, since target lists use both.
    pub fn delete_word(&mut self) {
        let chars: Vec<char> = self.text.chars().collect();
        let sep = |c: char| c.is_whitespace() || c == ',';
        let mut start = self.cursor;
        while start > 0 && sep(chars[start - 1]) {
            start -= 1;
        }
        while start > 0 && !sep(chars[start - 1]) {
            start -= 1;
        }
        let (from, to) = (self.byte_at(start), self.byte_at(self.cursor));
        self.text.replace_range(from..to, "");
        self.cursor = start;
    }

    /// Apply an editing key. Returns false for keys it doesn't handle, so
    /// the caller can use them (Enter, Tab, Esc, ...).
    pub fn handle_key(&mut self, key: &KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('u') if ctrl => self.clear(),
            KeyCode::Char('w') if ctrl => self.delete_word(),
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.len_chars(),
            KeyCode::Char(_) if ctrl => return false,
            KeyCode::Char(c) => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.len_chars()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.len_chars(),
            _ => return false,
        }
        true
    }

    /// The slice to draw in a field `width` columns wide, scrolled so the
    /// cursor stays visible, and the cursor's column within it.
    pub fn window(&self, width: usize) -> (String, usize) {
        if width == 0 {
            return (String::new(), 0);
        }
        let skip = (self.cursor + 1).saturating_sub(width);
        let shown = self.text.chars().skip(skip).take(width).collect();
        (shown, self.cursor - skip)
    }
}

/// Turn pasted text into one line: newlines and tabs (a column copied from
/// a spreadsheet or a list in a ticket) become commas, blank entries drop.
pub fn paste_as_list(pasted: &str) -> String {
    if !pasted.contains(['\n', '\r', '\t']) {
        return pasted.to_string();
    }
    pasted
        .split(['\n', '\r', '\t'])
        .map(|s| s.trim().trim_end_matches(','))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

impl Deref for TextInput {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for TextInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<&str> for TextInput {
    fn from(s: &str) -> Self {
        TextInput::new(s)
    }
}

impl From<String> for TextInput {
    fn from(s: String) -> Self {
        TextInput::new(s)
    }
}

impl PartialEq<&str> for TextInput {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn cursor_moves_and_inserts_mid_string() {
        let mut t = TextInput::new("10.0.0.1");
        for _ in 0..2 {
            t.handle_key(&key(KeyCode::Left));
        }
        t.insert('5');
        assert_eq!(t, "10.0.05.1");
        t.handle_key(&key(KeyCode::Home));
        t.handle_key(&key(KeyCode::Delete));
        assert_eq!(t, "0.0.05.1");
        t.handle_key(&key(KeyCode::End));
        t.handle_key(&key(KeyCode::Right));
        assert_eq!(t.cursor(), t.len_chars(), "right stops at the end");
    }

    #[test]
    fn ctrl_w_and_ctrl_u() {
        let mut t = TextInput::new("10.0.0.1, 10.0.0.2");
        t.handle_key(&ctrl('w'));
        assert_eq!(t, "10.0.0.1, ");
        t.handle_key(&ctrl('w'));
        assert_eq!(t, "");
        t.handle_key(&ctrl('w')); // on empty text: harmless
        t.insert_str("abc");
        t.handle_key(&ctrl('u'));
        assert_eq!(t, "");
        assert!(!t.handle_key(&ctrl('x')), "unknown ctrl keys pass through");
    }

    #[test]
    fn multibyte_text_never_panics() {
        let mut t = TextInput::new("héllo wörld");
        for code in [KeyCode::Left, KeyCode::Backspace, KeyCode::Delete] {
            for _ in 0..20 {
                t.handle_key(&key(code));
            }
            t.insert('ü');
        }
        t.delete_word();
        let (shown, cur) = t.window(3);
        assert!(shown.chars().count() <= 3 && cur < 3);
    }

    #[test]
    fn window_follows_the_cursor() {
        let t = TextInput::new("abcdefghij");
        assert_eq!(t.window(4), ("hij".to_string(), 3));
        assert_eq!(t.window(20), ("abcdefghij".to_string(), 10));
        assert_eq!(t.window(0), (String::new(), 0));
    }

    #[test]
    fn pasted_lists_become_commas() {
        assert_eq!(
            paste_as_list("10.0.0.1\r\n10.0.0.2\n\n  10.0.0.3,\n"),
            "10.0.0.1,10.0.0.2,10.0.0.3"
        );
        assert_eq!(paste_as_list("a\tb"), "a,b");
        assert_eq!(paste_as_list("one line, kept"), "one line, kept");
    }
}
