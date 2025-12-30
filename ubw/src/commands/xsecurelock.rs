use clap::Args;
use std::env;
use ubitwarden::api::BwApi;

use anyhow::Result;
use log::error;
use tokio::io::{self, AsyncReadExt};
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::xproto::*;
use x11rb::rust_connection::RustConnection;

#[derive(Args)]
pub struct XSecureLockArgs {
    /// email address
    #[arg(short, long)]
    pub email: String,

    /// server url
    #[arg(short, long)]
    pub server_url: String,
}

#[derive(Debug, Clone)]
struct Monitor {
    x: i16,
    y: i16,
    width: u16,
    height: u16,
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

async fn read_password() -> Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    let mut chars = Vec::new();

    let mut reader = io::stdin();

    let window_id_str = env::var("XSCREENSAVER_WINDOW")?;

    error!("XSCREENSAVER_WINDOW={window_id_str}");

    let window_id = if window_id_str.starts_with("0x") || window_id_str.starts_with("0X") {
        u32::from_str_radix(&window_id_str[2..], 16)?
    } else {
        window_id_str.parse()?
    };

    error!("Parsed window_id={window_id}");

    // Connect to X11
    let (conn, screen_num) = RustConnection::connect(None)?;
    let screen = &conn.setup().roots[screen_num];

    // Use the window_id directly as the drawable
    let drawable = window_id;
    error!("Using drawable={drawable} (0x{:x})", drawable);

    // Get window geometry
    let geometry = conn.get_geometry(drawable)?.reply()?;

    error!(
        "Window geometry: {}x{} at ({}, {})",
        geometry.width, geometry.height, geometry.x, geometry.y
    );

    // Detect monitors using RandR
    let monitors = detect_monitors(&conn, screen.root)?;
    error!("Detected {} monitors", monitors.len());
    for (i, mon) in monitors.iter().enumerate() {
        error!("Monitor {}: {}x{} at ({}, {})", i, mon.width, mon.height, mon.x, mon.y);
    }

    // Create graphics context with green color for visibility
    let gc = conn.generate_id()?;
    let gc_aux = CreateGCAux::new()
        .foreground(0x00FF00) // Green color
        .graphics_exposures(0);
    conn.create_gc(gc, drawable, &gc_aux)?;

    error!("Created GC with green foreground");

    // Map and raise the window to ensure it's visible
    conn.map_window(drawable)?;

    let config = ConfigureWindowAux::new().stack_mode(StackMode::ABOVE);
    conn.configure_window(drawable, &config)?;
    conn.flush()?;

    const DOT_RADIUS: i16 = 30; // Much larger dots
    const DOT_SPACING: i16 = 70;

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

        error!("Drawing {} dots on {} monitors", chars.len(), monitors.len());

        // Clear the entire drawable first to remove old dots
        conn.clear_area(false, drawable, 0, 0, geometry.width, geometry.height)?;

        // Draw dots for each character on each monitor
        let num_dots = i16::try_from(chars.len())?;
        let total_width = num_dots * DOT_SPACING;

        for (mon_idx, monitor) in monitors.iter().enumerate() {
            let center_x = monitor.x + i16::try_from(monitor.width / 2)?;
            let center_y = monitor.y + i16::try_from(monitor.height / 2)?;
            let start_x = center_x - total_width / 2;

            error!("Monitor {}: drawing at center ({}, {})", mon_idx, center_x, center_y);

            // Draw filled rectangles (dots) instead of arcs for simplicity
            let mut rects = Vec::new();
            for i in 0..num_dots {
                let x = start_x + i * DOT_SPACING;
                let y = center_y;

                // Create filled rectangle (dot)
                rects.push(Rectangle {
                    x: x - DOT_RADIUS,
                    y: y - DOT_RADIUS,
                    width: u16::try_from(DOT_RADIUS * 2)?,
                    height: u16::try_from(DOT_RADIUS * 2)?,
                });
            }

            if !rects.is_empty() {
                conn.poly_fill_rectangle(drawable, gc, &rects)?;
            }
        }

        conn.flush()?;
        error!("Flushed to display");
    }

    // Clear the window when done
    conn.clear_area(false, drawable, 0, 0, geometry.width, geometry.height)?;
    conn.flush()?;

    Ok(chars)
}

pub async fn command_xsecurelock(args: XSecureLockArgs) -> Result<()> {
    let password_chars = read_password().await?;

    let password = String::from_utf8(password_chars)?;

    //
    // validate the password
    //

    let api = BwApi::new(&args.email, &args.server_url)?;

    api.auth(password).await?;

    Ok(())
}
