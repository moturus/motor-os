//! Read copy-mode status from rmux's rendered screen, including frame diffs.
#[allow(dead_code)]
#[path = "../bin/rmux/src/ansi.rs"]
mod ansi;
#[allow(dead_code)]
#[path = "../bin/rmux/src/grid.rs"]
mod grid;

use std::io::Read;

fn latest_indicator(bytes: &[u8]) -> Option<String> {
    // The pipe-driven client receives no size report and uses this fallback.
    let mut grid = grid::Grid::new(24, 80);
    let mut parser = ansi::Parser::new();
    let mut latest = None;
    parser.feed(bytes, &mut |action| {
        grid.apply(action);
        let line = grid.line(23);
        let Some(counts) = line
            .strip_prefix("-- copy mode -- [")
            .and_then(|text| text.strip_suffix(']'))
        else {
            return;
        };
        let Some((above, total)) = counts.split_once('/') else {
            return;
        };
        if [above, total]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            latest = Some(format!("copy mode -- [{counts}]"));
        }
    });
    latest
}

fn main() -> std::io::Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    if let Some(indicator) = latest_indicator(&bytes) {
        println!("{indicator}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../bin/rmux/src/screen.rs"]
mod screen;

#[cfg(test)]
mod tests {
    use super::*;

    fn paint(screen: &mut screen::Screen, status: &str) -> Vec<u8> {
        let mut frame = screen::Frame::new(24, 80);
        let cells: Vec<_> = status
            .chars()
            .map(|ch| grid::Cell {
                ch,
                ..Default::default()
            })
            .collect();
        frame.set_row(23, &cells);
        screen.draw(frame)
    }

    #[test]
    fn differential_status_replaces_the_initial_indicator() {
        let mut screen = screen::Screen::new();
        let mut bytes = paint(&mut screen, "-- copy mode -- [0/28]");
        bytes.extend(paint(&mut screen, "-- copy mode -- [28/28]"));
        bytes.extend(paint(&mut screen, "[0] 0:rush*"));
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("copy mode -- [0/28]"));
        assert!(!raw.contains("copy mode -- [28/28]"));
        assert_eq!(
            latest_indicator(&bytes).as_deref(),
            Some("copy mode -- [28/28]")
        );
    }

    #[test]
    fn incomplete_scroll_is_not_reported_as_reaching_the_top() {
        let mut screen = screen::Screen::new();
        let mut bytes = paint(&mut screen, "-- copy mode -- [0/28]");
        assert_eq!(
            latest_indicator(&bytes).as_deref(),
            Some("copy mode -- [0/28]")
        );
        bytes.extend(paint(&mut screen, "-- copy mode -- [7/28]"));
        bytes.extend(paint(&mut screen, "[0] 0:rush*"));
        assert_eq!(
            latest_indicator(&bytes).as_deref(),
            Some("copy mode -- [7/28]")
        );
    }

    #[test]
    fn absent_or_malformed_status_is_not_an_indicator() {
        assert_eq!(latest_indicator(b""), None);
        for status in ["-- copy mode -- [/28]", "-- copy mode -- [a/28]"] {
            let bytes = paint(&mut screen::Screen::new(), status);
            assert_eq!(latest_indicator(&bytes), None);
        }
    }
}
