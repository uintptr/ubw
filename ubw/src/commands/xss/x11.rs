use std::env;
use std::io::{self, Read};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{error, info};
use ubitwarden::api::BwApi;
use ubitwarden_agent::agent::UBWAgent;
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::xproto::{
    Arc, ChangeGCAux, Char2b, ConfigureWindowAux, ConnectionExt, CreateGCAux, Font, Gcontext, Pixmap, Rectangle,
    Segment, StackMode, Window,
};
use x11rb::rust_connection::RustConnection;

use crate::commands::agent::server::spawn_server;
use crate::commands::xss::XSecureLockArgs;

#[derive(Debug, Clone)]
struct Monitor {
    x: i16,
    y: i16,
    width: u16,
    height: u16,
}

//
// palette (24-bit TrueColor)
//
const BG: u32 = 0x000E_1015;
const CARD: u32 = 0x001B_1E26;
const CARD_BORDER: u32 = 0x002C_313C;
const FIELD: u32 = 0x0012_141A;
const TEXT: u32 = 0x00E6_E9EF;
const MUTED: u32 = 0x007A_8394;
const ACCENT: u32 = 0x0088_C0D0;
const WARN: u32 = 0x00EB_CB8B;
const ERROR: u32 = 0x00E0_6C75;

//
// card layout (pixels, relative to the card's top-left corner)
//
const CARD_MIN_WIDTH: u16 = 480;
const CARD_HEIGHT: u16 = 264;
const CARD_RADIUS: u16 = 18;
const CARD_PAD: i16 = 40;
const ICON_TOP: i16 = 30;
const PROMPT_BASELINE: i16 = 122;
const FIELD_TOP: i16 = 144;
const FIELD_HEIGHT: u16 = 52;
const FIELD_RADIUS: u16 = 12;
const FIELD_INNER_PAD: i16 = 18;
const STATUS_BASELINE: i16 = 234;
const DOT_RADIUS: u16 = 7;
const DOT_SPACING: i16 = 26;

const FULL_CIRCLE: i16 = 360 * 64;
const HALF_CIRCLE: i16 = 180 * 64;

const TITLE_FONTS: &[&str] = &[
    "-*-helvetica-bold-r-normal--25-*-*-*-*-*-iso8859-1",
    "-*-*-bold-r-normal--25-*-*-*-p-*-iso8859-1",
    "-*-*-bold-r-*-*-24-*-*-*-*-*-iso8859-1",
    "10x20",
    "fixed",
];
const SMALL_FONTS: &[&str] = &[
    "-*-helvetica-medium-r-normal--17-*-*-*-*-*-iso8859-1",
    "-*-*-medium-r-normal--17-*-*-*-p-*-iso8859-1",
    "9x15",
    "fixed",
];

const HINT_TEXT: &[u8] = b"Enter to unlock  \xb7  Esc to clear";
const VERIFYING_TEXT: &[u8] = b"Verifying...";
const FAILED_TEXT: &[u8] = b"Authentication failed";

/// How long the failure message stays up before we exit
const FAILURE_DISPLAY: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Typing,
    Verifying,
    Failed,
}

fn to_i16(v: u16) -> i16 {
    i16::try_from(v).unwrap_or(i16::MAX)
}

fn to_u16(v: i16) -> u16 {
    u16::try_from(v).unwrap_or(0)
}

/// X core fonts are 8-bit; map to latin-1 and replace anything else
fn latin1(s: &str) -> Vec<u8> {
    s.chars()
        .take(255)
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect()
}

/// Number of UTF-8 characters in `bytes` (counts every non-continuation byte)
fn char_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b & 0xC0 != 0x80).count()
}

/// Remove the last UTF-8 character (not just the last byte)
fn pop_char(bytes: &mut Vec<u8>) {
    while let Some(b) = bytes.pop() {
        if b & 0xC0 != 0x80 {
            break;
        }
    }
}

fn open_first_font(conn: &RustConnection, names: &[&str]) -> Result<Font> {
    let font = conn.generate_id().context("Failed to generate X11 font ID")?;
    for name in names {
        // open_font errors are asynchronous; check() waits for the server's verdict
        if conn.open_font(font, name.as_bytes())?.check().is_ok() {
            info!("Loaded font: {name}");
            return Ok(font);
        }
    }
    bail!("Unable to load any of the fonts: {names:?}")
}

fn detect_monitors(conn: &impl Connection, root: u32) -> Result<Vec<Monitor>> {
    // Try to use RandR to get monitor information
    let screen_res = conn.randr_get_screen_resources(root)?.reply();

    if let Ok(screen_res) = screen_res {
        let mut monitors = Vec::new();

        for crtc in &screen_res.crtcs {
            let crtc_info = conn.randr_get_crtc_info(*crtc, 0)?.reply();
            if let Ok(info) = crtc_info {
                // Only add active CRTCs (ones with outputs)
                if info.width > 0 && info.height > 0 {
                    monitors.push(Monitor {
                        x: info.x,
                        y: info.y,
                        width: info.width,
                        height: info.height,
                    });
                }
            }
        }

        if !monitors.is_empty() {
            return Ok(monitors);
        }
    }

    // Fallback: use root window geometry as single monitor
    let geometry = conn.get_geometry(root)?.reply()?;
    Ok(vec![Monitor {
        x: 0,
        y: 0,
        width: geometry.width,
        height: geometry.height,
    }])
}

/// The part of each monitor covered by the window, in window coordinates.
/// Under xsecurelock the window spans the whole screen, so this is just the monitor list.
fn visible_regions(monitors: &[Monitor], (win_x, win_y): (i16, i16), width: u16, height: u16) -> Vec<Monitor> {
    let (wx, wy) = (i32::from(win_x), i32::from(win_y));
    let (wr, wb) = (
        wx.saturating_add(i32::from(width)),
        wy.saturating_add(i32::from(height)),
    );

    let regions: Vec<Monitor> = monitors
        .iter()
        .filter_map(|m| {
            let left = i32::from(m.x).max(wx);
            let top = i32::from(m.y).max(wy);
            let right = i32::from(m.x).saturating_add(i32::from(m.width)).min(wr);
            let bottom = i32::from(m.y).saturating_add(i32::from(m.height)).min(wb);
            Some(Monitor {
                x: i16::try_from(left.saturating_sub(wx)).ok()?,
                y: i16::try_from(top.saturating_sub(wy)).ok()?,
                width: u16::try_from(right.saturating_sub(left)).ok().filter(|&w| w > 0)?,
                height: u16::try_from(bottom.saturating_sub(top)).ok().filter(|&h| h > 0)?,
            })
        })
        .collect();

    if regions.is_empty() {
        vec![Monitor {
            x: 0,
            y: 0,
            width,
            height,
        }]
    } else {
        regions
    }
}

fn parse_window_id() -> Result<Window> {
    let window_id_str = env::var("XSCREENSAVER_WINDOW").context("XSCREENSAVER_WINDOW environment variable not set")?;

    info!("XSCREENSAVER_WINDOW={window_id_str}");

    if let Some(hex) = window_id_str.strip_prefix("0x").or_else(|| window_id_str.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).with_context(|| format!("Invalid hex window ID: {window_id_str}"))
    } else {
        window_id_str
            .parse()
            .with_context(|| format!("Invalid window ID: {window_id_str}"))
    }
}

/// The unlock prompt: one card, rendered off-screen into a pixmap and copied to the center of every monitor
struct LockScreen {
    conn: RustConnection,
    window: Window,
    win_width: u16,
    win_height: u16,
    monitors: Vec<Monitor>,
    gc: Gcontext,
    card: Pixmap,
    card_width: u16,
    title_font: Font,
    small_font: Font,
    prompt: Vec<u8>,
    prompt_width: i16,
}

impl LockScreen {
    fn new(prompt: &str) -> Result<Self> {
        let window = parse_window_id()?;
        info!("Using window={window} (0x{window:x})");

        let (conn, screen_num) = RustConnection::connect(None).context("Failed to connect to X11 display")?;
        let root = conn
            .setup()
            .roots
            .get(screen_num)
            .ok_or_else(|| anyhow::anyhow!("Invalid screen number: {screen_num}"))?
            .root;

        let geometry = conn
            .get_geometry(window)
            .context("Failed to request window geometry")?
            .reply()
            .context("Failed to get window geometry reply")?;

        info!(
            "Window geometry: {}x{} at ({}, {}), depth {}",
            geometry.width, geometry.height, geometry.x, geometry.y, geometry.depth
        );

        let monitors = detect_monitors(&conn, root)?;
        info!("Detected {} monitors", monitors.len());
        for (i, mon) in monitors.iter().enumerate() {
            info!("Monitor {}: {}x{} at ({}, {})", i, mon.width, mon.height, mon.x, mon.y);
        }

        // monitors are in root coordinates; we draw in window coordinates
        let origin = conn
            .translate_coordinates(window, root, 0, 0)
            .context("Failed to request window position")?
            .reply()
            .context("Failed to get window position reply")?;
        let monitors = visible_regions(&monitors, (origin.dst_x, origin.dst_y), geometry.width, geometry.height);
        for (i, region) in monitors.iter().enumerate() {
            info!(
                "Region {}: {}x{} at ({}, {}) in window",
                i, region.width, region.height, region.x, region.y
            );
        }

        let title_font = open_first_font(&conn, TITLE_FONTS)?;
        let small_font = open_first_font(&conn, SMALL_FONTS)?;

        let prompt = latin1(prompt);
        let prompt_width = text_width(&conn, title_font, &prompt)?;

        // wide enough for the prompt, but never wider than the narrowest monitor
        let narrowest = monitors.iter().map(|m| m.width).min().unwrap_or(CARD_MIN_WIDTH);
        let card_width = to_u16(prompt_width.saturating_add(CARD_PAD.saturating_mul(3)))
            .max(CARD_MIN_WIDTH)
            .min(narrowest.saturating_sub(32));

        let gc = conn.generate_id().context("Failed to generate X11 graphics context ID")?;
        conn.create_gc(gc, window, &CreateGCAux::new().graphics_exposures(0))
            .context("Failed to create X11 graphics context")?;

        let card = conn.generate_id().context("Failed to generate X11 pixmap ID")?;
        conn.create_pixmap(geometry.depth, card, window, card_width, CARD_HEIGHT)
            .context("Failed to create card pixmap")?;

        // Map and raise the window to ensure it's visible
        conn.map_window(window).context("Failed to map X11 window")?;
        conn.configure_window(window, &ConfigureWindowAux::new().stack_mode(StackMode::ABOVE))
            .context("Failed to configure X11 window")?;

        let screen = Self {
            conn,
            window,
            win_width: geometry.width,
            win_height: geometry.height,
            monitors,
            gc,
            card,
            card_width,
            title_font,
            small_font,
            prompt,
            prompt_width,
        };

        // paint the backdrop once; afterwards only the cards change
        screen.set_fg(BG)?;
        screen.conn.poly_fill_rectangle(
            window,
            gc,
            &[Rectangle {
                x: 0,
                y: 0,
                width: screen.win_width,
                height: screen.win_height,
            }],
        )?;

        Ok(screen)
    }

    fn set_fg(&self, color: u32) -> Result<()> {
        self.conn.change_gc(self.gc, &ChangeGCAux::new().foreground(color))?;
        Ok(())
    }

    fn fill_round_rect(&self, x: i16, y: i16, width: u16, height: u16, radius: u16) -> Result<()> {
        let d = radius.saturating_mul(2);
        let r = to_i16(radius);
        let right = x.saturating_add(to_i16(width)).saturating_sub(to_i16(d));
        let bottom = y.saturating_add(to_i16(height)).saturating_sub(to_i16(d));

        let rects = [
            Rectangle {
                x: x.saturating_add(r),
                y,
                width: width.saturating_sub(d),
                height,
            },
            Rectangle {
                x,
                y: y.saturating_add(r),
                width,
                height: height.saturating_sub(d),
            },
        ];
        let corners = [(x, y), (right, y), (x, bottom), (right, bottom)].map(|(x, y)| Arc {
            x,
            y,
            width: d,
            height: d,
            angle1: 0,
            angle2: FULL_CIRCLE,
        });

        self.conn.poly_fill_rectangle(self.card, self.gc, &rects)?;
        self.conn.poly_fill_arc(self.card, self.gc, &corners)?;
        Ok(())
    }

    fn draw_text_centered(&self, font: Font, fg: u32, bg: u32, baseline: i16, text: &[u8], width: i16) -> Result<()> {
        self.conn
            .change_gc(self.gc, &ChangeGCAux::new().foreground(fg).background(bg).font(font))?;
        let x = to_i16(self.card_width).saturating_sub(width) / 2;
        self.conn.image_text8(self.card, self.gc, x, baseline, text)?;
        Ok(())
    }

    fn draw_lock_icon(&self, cx: i16, top: i16, color: u32) -> Result<()> {
        // shackle: upper half of an ellipse plus two short legs into the body
        self.conn
            .change_gc(self.gc, &ChangeGCAux::new().foreground(color).line_width(4))?;
        let mid = top.saturating_add(13);
        let legs_end = top.saturating_add(22);
        self.conn.poly_arc(
            self.card,
            self.gc,
            &[Arc {
                x: cx.saturating_sub(12),
                y: top,
                width: 24,
                height: 26,
                angle1: 0,
                angle2: HALF_CIRCLE,
            }],
        )?;
        self.conn.poly_segment(
            self.card,
            self.gc,
            &[-12, 12].map(|dx| Segment {
                x1: cx.saturating_add(dx),
                y1: mid,
                x2: cx.saturating_add(dx),
                y2: legs_end,
            }),
        )?;

        // body
        let body_top = top.saturating_add(20);
        self.fill_round_rect(cx.saturating_sub(19), body_top, 38, 30, 6)?;

        // keyhole
        self.set_fg(CARD)?;
        self.conn.poly_fill_arc(
            self.card,
            self.gc,
            &[Arc {
                x: cx.saturating_sub(4),
                y: body_top.saturating_add(8),
                width: 8,
                height: 8,
                angle1: 0,
                angle2: FULL_CIRCLE,
            }],
        )?;
        self.conn.poly_fill_rectangle(
            self.card,
            self.gc,
            &[Rectangle {
                x: cx.saturating_sub(1),
                y: body_top.saturating_add(13),
                width: 3,
                height: 9,
            }],
        )?;
        Ok(())
    }

    fn draw_field(&self, chars: usize, phase: Phase, accent: u32) -> Result<()> {
        let x = CARD_PAD;
        let width = to_u16(to_i16(self.card_width).saturating_sub(CARD_PAD.saturating_mul(2)));
        let center_x = to_i16(self.card_width) / 2;
        let center_y = FIELD_TOP.saturating_add(to_i16(FIELD_HEIGHT / 2));

        let border = if phase == Phase::Typing && chars == 0 {
            CARD_BORDER
        } else {
            accent
        };
        self.set_fg(border)?;
        self.fill_round_rect(x, FIELD_TOP, width, FIELD_HEIGHT, FIELD_RADIUS)?;
        self.set_fg(FIELD)?;
        self.fill_round_rect(
            x.saturating_add(2),
            FIELD_TOP.saturating_add(2),
            width.saturating_sub(4),
            FIELD_HEIGHT.saturating_sub(4),
            FIELD_RADIUS.saturating_sub(2),
        )?;

        if chars == 0 {
            // a muted caret so the empty field still reads as "type here"
            self.set_fg(MUTED)?;
            self.conn.poly_fill_rectangle(
                self.card,
                self.gc,
                &[Rectangle {
                    x: center_x.saturating_sub(1),
                    y: center_y.saturating_sub(11),
                    width: 2,
                    height: 22,
                }],
            )?;
            return Ok(());
        }

        // as many dots as fit; a long password just fills the field
        let usable = to_i16(width).saturating_sub(FIELD_INNER_PAD.saturating_mul(2));
        let capacity = usize::try_from(usable / DOT_SPACING).unwrap_or(1).max(1);
        let shown = i16::try_from(chars.min(capacity)).unwrap_or(1);
        let diameter = DOT_RADIUS.saturating_mul(2);
        let span = shown
            .saturating_sub(1)
            .saturating_mul(DOT_SPACING)
            .saturating_add(to_i16(diameter));
        let start_x = center_x.saturating_sub(span / 2);
        let top = center_y.saturating_sub(to_i16(DOT_RADIUS));

        let dots: Vec<Arc> = (0..shown)
            .map(|i| Arc {
                x: start_x.saturating_add(i.saturating_mul(DOT_SPACING)),
                y: top,
                width: diameter,
                height: diameter,
                angle1: 0,
                angle2: FULL_CIRCLE,
            })
            .collect();

        self.set_fg(if phase == Phase::Typing { TEXT } else { accent })?;
        self.conn.poly_fill_arc(self.card, self.gc, &dots)?;
        Ok(())
    }

    fn render(&self, chars: usize, phase: Phase) -> Result<()> {
        let (accent, status, status_color) = match phase {
            Phase::Typing => (ACCENT, HINT_TEXT, MUTED),
            Phase::Verifying => (WARN, VERIFYING_TEXT, WARN),
            Phase::Failed => (ERROR, FAILED_TEXT, ERROR),
        };

        // backdrop behind the rounded corners, then a 1px border and the card body
        self.set_fg(BG)?;
        self.conn.poly_fill_rectangle(
            self.card,
            self.gc,
            &[Rectangle {
                x: 0,
                y: 0,
                width: self.card_width,
                height: CARD_HEIGHT,
            }],
        )?;
        self.set_fg(CARD_BORDER)?;
        self.fill_round_rect(0, 0, self.card_width, CARD_HEIGHT, CARD_RADIUS)?;
        self.set_fg(CARD)?;
        self.fill_round_rect(
            1,
            1,
            self.card_width.saturating_sub(2),
            CARD_HEIGHT.saturating_sub(2),
            CARD_RADIUS.saturating_sub(1),
        )?;

        self.draw_lock_icon(to_i16(self.card_width) / 2, ICON_TOP, accent)?;
        self.draw_text_centered(
            self.title_font,
            TEXT,
            CARD,
            PROMPT_BASELINE,
            &self.prompt,
            self.prompt_width,
        )?;
        self.draw_field(chars, phase, accent)?;
        let status_width = text_width(&self.conn, self.small_font, status)?;
        self.draw_text_centered(
            self.small_font,
            status_color,
            CARD,
            STATUS_BASELINE,
            status,
            status_width,
        )?;

        self.present()
    }

    /// Copy the finished card to the center of every monitor in one go (no flicker)
    fn present(&self) -> Result<()> {
        for monitor in &self.monitors {
            let x = monitor
                .x
                .saturating_add(to_i16(monitor.width.saturating_sub(self.card_width) / 2));
            let y = monitor.y.saturating_add(to_i16(monitor.height.saturating_sub(CARD_HEIGHT) / 2));
            self.conn
                .copy_area(
                    self.card,
                    self.window,
                    self.gc,
                    0,
                    0,
                    x,
                    y,
                    self.card_width,
                    CARD_HEIGHT,
                )
                .context("Failed to copy card to X11 window")?;
        }
        self.conn.flush().context("Failed to flush X11 display")?;
        Ok(())
    }

    fn read_password(&self) -> Result<Vec<u8>> {
        let mut stdin = io::stdin().lock();
        let mut buf = [0u8; 1];
        let mut password = Vec::new();

        self.render(0, Phase::Typing)?;

        loop {
            stdin.read_exact(&mut buf).context("Failed to read password input")?;

            match buf {
                // ignore Enter on an empty field instead of submitting nothing
                [b'\n' | b'\r'] if password.is_empty() => continue,
                [b'\n' | b'\r'] => break,
                // backspace / delete
                [8 | 127] => pop_char(&mut password),
                // Esc / Ctrl-U: start over
                [27 | 21] => password.clear(),
                [b] => password.push(b),
            }

            self.render(char_count(&password), Phase::Typing)?;
        }

        Ok(password)
    }
}

impl Drop for LockScreen {
    fn drop(&mut self) {
        // best effort: leave nothing behind on the window
        let _ = self.conn.free_pixmap(self.card);
        let _ = self.conn.free_gc(self.gc);
        let _ = self.conn.close_font(self.title_font);
        let _ = self.conn.close_font(self.small_font);
        let _ = self.conn.clear_area(false, self.window, 0, 0, self.win_width, self.win_height);
        let _ = self.conn.flush();
    }
}

fn text_width(conn: &RustConnection, font: Font, text: &[u8]) -> Result<i16> {
    let chars: Vec<Char2b> = text.iter().map(|&b| Char2b { byte1: 0, byte2: b }).collect();
    let extents = conn
        .query_text_extents(font, &chars)
        .context("Failed to query text extents")?
        .reply()
        .context("Failed to get text extents reply")?;
    Ok(i16::try_from(extents.overall_width).unwrap_or(i16::MAX))
}

fn store_password(args: &XSecureLockArgs, password: &str) -> Result<()> {
    let mut agent = if let Ok(v) = UBWAgent::client() {
        v
    } else {
        info!("unable to talk to the server. spawning a new one");
        spawn_server().context("Failed to spawn credential cache server")?;
        UBWAgent::client().context("Failed to connect to credential cache server after spawning")?
    };

    agent
        .credentials_store(&args.email, &args.server_url, password)
        .context("Failed to store credentials in cache")?;

    Ok(())
}

pub fn command_xsecurelock(args: &XSecureLockArgs) -> Result<()> {
    let screen = LockScreen::new(&format!("Password for {}", args.email))?;

    let password_bytes = screen.read_password()?;
    let chars = char_count(&password_bytes);
    let password = String::from_utf8(password_bytes).context("Password contains invalid UTF-8 characters")?;

    //
    // validate the password
    //

    screen.render(chars, Phase::Verifying)?;

    let auth = BwApi::new(&args.email, &args.server_url)
        .with_context(|| format!("Failed to initialize API client for {}", args.email))
        .and_then(|api| api.auth(&password).context("Authentication failed"));

    if let Err(e) = auth {
        error!("auth failure");
        if screen.render(chars, Phase::Failed).is_ok() {
            thread::sleep(FAILURE_DISPLAY);
        }
        return Err(e);
    }

    if let Err(e) = store_password(args, &password) {
        error!("Unable to store password ({e})");
    }

    Ok(())
}
