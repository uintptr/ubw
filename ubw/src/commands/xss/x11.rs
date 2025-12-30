use std::env;
use ubitwarden::api::BwApi;
use ubitwarden_agent::agent::UBWAgent;

use anyhow::Result;
use log::{error, info};
use tokio::io::{self, AsyncReadExt};
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::xproto::{ConfigureWindowAux, ConnectionExt, CreateGCAux, Rectangle, StackMode};
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

const DOT_RADIUS: i16 = 30; // Much larger dots
const DOT_SPACING: i16 = 70;
const TEXT_OFFSET: i16 = 80; // Distance above the dots to draw text

fn draw_prompt_text(conn: &RustConnection, drawable: u32, gc: u32, monitors: &[Monitor], text: &str) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }

    let text_bytes = text.as_bytes();

    for monitor in monitors {
        let center_x = monitor.x.saturating_add(i16::try_from(monitor.width / 2)?);
        let center_y = monitor.y.saturating_add(i16::try_from(monitor.height / 2)?);

        // Estimate text width (rough approximation: 20 pixels per character for large font)
        let text_width = i16::try_from(text_bytes.len())?.saturating_mul(20);
        let text_x = center_x.saturating_sub(text_width / 2);
        let text_y = center_y.saturating_sub(TEXT_OFFSET);

        conn.image_text8(drawable, gc, text_x, text_y, text_bytes)?;
    }

    conn.flush()?;
    Ok(())
}

fn draw_password_dots(
    conn: &RustConnection,
    drawable: u32,
    gc: u32,
    monitors: &[Monitor],
    num_chars: usize,
) -> Result<()> {
    let num_dots = i16::try_from(num_chars)?;
    let total_width = num_dots.saturating_mul(DOT_SPACING);

    for (mon_idx, monitor) in monitors.iter().enumerate() {
        let center_x = monitor.x.saturating_add(i16::try_from(monitor.width / 2)?);
        let center_y = monitor.y.saturating_add(i16::try_from(monitor.height / 2)?);
        let start_x = center_x.saturating_sub(total_width / 2);

        info!("Monitor {mon_idx}: drawing at center ({center_x}, {center_y})");

        // Draw filled rectangles (dots) instead of arcs for simplicity
        let mut rects = Vec::new();
        for i in 0..num_dots {
            let x = start_x.saturating_add(i.saturating_mul(DOT_SPACING));
            let y = center_y;

            // Create filled rectangle (dot)
            rects.push(Rectangle {
                x: x.saturating_sub(DOT_RADIUS),
                y: y.saturating_sub(DOT_RADIUS),
                width: u16::try_from(DOT_RADIUS.saturating_mul(2))?,
                height: u16::try_from(DOT_RADIUS.saturating_mul(2))?,
            });
        }

        if !rects.is_empty() {
            conn.poly_fill_rectangle(drawable, gc, &rects)?;
        }
    }

    conn.flush()?;
    info!("Flushed to display");

    Ok(())
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

async fn read_password(prompt: &str) -> Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    let mut chars = Vec::new();

    let mut reader = io::stdin();

    let window_id_str = env::var("XSCREENSAVER_WINDOW")?;

    info!("XSCREENSAVER_WINDOW={window_id_str}");

    let window_id = if window_id_str.starts_with("0x") || window_id_str.starts_with("0X") {
        u32::from_str_radix(&window_id_str[2..], 16)?
    } else {
        window_id_str.parse()?
    };

    info!("Parsed window_id={window_id}");

    // Connect to X11
    let (conn, screen_num) = RustConnection::connect(None)?;
    let screen = &conn.setup().roots[screen_num];

    // Use the window_id directly as the drawable
    let drawable = window_id;
    info!("Using drawable={drawable} (0x{drawable:x})");

    // Get window geometry
    let geometry = conn.get_geometry(drawable)?.reply()?;

    info!(
        "Window geometry: {}x{} at ({}, {})",
        geometry.width, geometry.height, geometry.x, geometry.y
    );

    // Clear the window at the start to remove any previous dots
    conn.clear_area(false, drawable, 0, 0, geometry.width, geometry.height)?;
    conn.flush()?;

    // Detect monitors using RandR
    let monitors = detect_monitors(&conn, screen.root)?;
    info!("Detected {} monitors", monitors.len());
    for (i, mon) in monitors.iter().enumerate() {
        info!("Monitor {}: {}x{} at ({}, {})", i, mon.width, mon.height, mon.x, mon.y);
    }

    // Try to load a larger font - try common font names
    let font = conn.generate_id()?;
    let font_names = [
        b"-*-*-bold-r-*-*-34-*-*-*-*-*-*-*" as &[u8],
        b"-*-*-*-*-*-*-34-*-*-*-*-*-*-*",
        b"-*-*-bold-r-*-*-24-*-*-*-*-*-*-*",
        b"10x20",
        b"9x15",
        b"fixed",
    ];

    let mut font_loaded = false;
    for font_name in &font_names {
        if conn.open_font(font, font_name).is_ok() {
            info!("Loaded font: {:?}", std::str::from_utf8(font_name).unwrap_or("unknown"));
            font_loaded = true;
            break;
        }
    }

    // Create graphics context with green color for visibility
    let gc = conn.generate_id()?;
    let mut gc_aux = CreateGCAux::new()
        .foreground(0x0000_FF00) // Green color
        .graphics_exposures(0);

    if font_loaded {
        gc_aux = gc_aux.font(font);
    }

    conn.create_gc(gc, drawable, &gc_aux)?;

    info!("Created GC with green foreground");

    // Map and raise the window to ensure it's visible
    conn.map_window(drawable)?;

    let config = ConfigureWindowAux::new().stack_mode(StackMode::ABOVE);
    conn.configure_window(drawable, &config)?;
    conn.flush()?;

    // Draw the prompt text immediately
    draw_prompt_text(&conn, drawable, gc, &monitors, prompt)?;

    loop {
        reader.read_exact(&mut buf).await?;

        if buf[0] == b'\n' || buf[0] == b'\r' {
            break;
        }

        // Handle backspace
        if buf[0] == 127 || buf[0] == 8 {
            chars.pop();
        } else if buf[0] == 27 {
            // ESC key - reset everything
            chars.clear();
        } else {
            chars.push(buf[0]);
        }

        info!("Drawing {} dots on {} monitors", chars.len(), monitors.len());

        // Clear the entire drawable first to remove old dots
        conn.clear_area(false, drawable, 0, 0, geometry.width, geometry.height)?;

        // Draw the prompt text
        draw_prompt_text(&conn, drawable, gc, &monitors, prompt)?;

        // Draw dots for each character on each monitor
        draw_password_dots(&conn, drawable, gc, &monitors, chars.len())?;
    }

    // Clear the window when done
    conn.clear_area(false, drawable, 0, 0, geometry.width, geometry.height)?;
    conn.flush()?;

    Ok(chars)
}

async fn store_password(args: &XSecureLockArgs, password: &str) -> Result<()> {
    let mut agent = if let Ok(v) = UBWAgent::new().await {
        v
    } else {
        info!("unable to talk to the server. spawning a new one");
        spawn_server().await?;
        UBWAgent::new().await?
    };

    agent.store_credentials(&args.email, &args.server_url, password).await?;

    Ok(())
}

pub async fn command_xsecurelock(args: XSecureLockArgs) -> Result<()> {
    let prompt = format!("Password for {}", args.email);

    let password_chars = read_password(&prompt).await?;

    let password = String::from_utf8(password_chars)?;

    //
    // validate the password
    //

    let api = BwApi::new(&args.email, &args.server_url)?;

    if let Err(e) = api.auth(&password).await {
        error!("auth failure");
        return Err(e.into());
    }

    if let Err(e) = store_password(&args, &password).await {
        error!("Unable to store password ({e})");
    }

    Ok(())
}
