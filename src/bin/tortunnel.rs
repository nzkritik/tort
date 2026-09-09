//! Tor Traffic Tunnel — a GTK4 front end for tort.
//!
//! Unprivileged by design. Every privileged operation goes to the daemon, which
//! authorizes it through polkit; the desktop's own authentication dialog appears
//! when needed. Nothing here runs as root, which matters for a process that also
//! renders widgets and parses network data.
//!
//! Requests are made on worker threads. The daemon's `up` takes tens of seconds
//! to bootstrap tor, and a GUI that blocks its main loop for that long is a GUI
//! that appears to have crashed.

use gtk4 as gtk;
use gtk::prelude::*;
use gtk::{glib, Application, ApplicationWindow, Orientation};
use std::cell::RefCell;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, RawFd};
use std::rc::Rc;

use tort::control::Circuit;
use tort::proto::{Request, Response, StatusReport};

const APP_ID: &str = "io.github.nzkritik.tortunnel";

/// How often to refresh, in seconds. Circuits persist for minutes, so polling
/// harder would burn the exit-lookup quota without telling the user anything new.
const REFRESH_SECONDS: u32 = 10;

/// Colours for circuits, reused across the list and (later) the map.
///
/// Chosen to stay distinguishable with the common forms of colour blindness;
/// the circuit number is always shown alongside, so colour is never the only
/// carrier of the information.
const CIRCUIT_COLOURS: [&str; 6] = [
    "#4e9bd6", // blue
    "#e6a23c", // amber
    "#7fbf7f", // green
    "#c678dd", // violet
    "#e06c75", // red
    "#56b6c2", // cyan
];

/// What a worker thread finished doing.
enum Update {
    Status(Box<StatusReport>),
    /// One line the daemon wrote while working - tor's bootstrap progress.
    Progress(String),
    Circuits(Vec<Circuit>),
    /// A long operation finished; the text is for the activity line.
    Done(String),
    Failed(String),
    /// polkit refused. Distinguished from a failure: nothing was attempted, and
    /// the remedy is a password or a policy rather than a bug report.
    Denied(String),
    Busy(bool),
}

fn main() -> glib::ExitCode {
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &Application) {
    let (sender, receiver) = async_channel::unbounded::<Update>();

    // --- top bar ------------------------------------------------------------
    let connect_button = gtk::Button::with_label("Connect");
    connect_button.add_css_class("suggested-action");

    let shell_button = gtk::Button::with_label("Run shell");
    let app_button = gtk::Button::with_label("Run app…");

    let header = gtk::HeaderBar::new();
    let title = gtk::Label::new(Some("Tor Traffic Tunnel"));
    title.add_css_class("title");
    header.set_title_widget(Some(&title));
    header.pack_start(&connect_button);
    header.pack_end(&app_button);
    header.pack_end(&shell_button);

    // --- top left: status ---------------------------------------------------
    let indicator = gtk::Label::new(Some("●"));
    indicator.add_css_class("title-1");
    let state_label = gtk::Label::new(Some("Checking…"));
    state_label.set_xalign(0.0);
    state_label.add_css_class("title-4");

    // Progress sits directly under the state text, beside the indicator, so
    // the eye follows one column while tor bootstraps.
    let progress_label = gtk::Label::new(None);
    progress_label.set_xalign(0.0);
    progress_label.add_css_class("dim-label");
    progress_label.add_css_class("monospace");
    progress_label.set_visible(false);

    let state_column = gtk::Box::new(Orientation::Vertical, 2);
    state_column.append(&state_label);
    state_column.append(&progress_label);

    let state_row = gtk::Box::new(Orientation::Horizontal, 10);
    state_row.append(&indicator);
    state_row.append(&state_column);

    let detail_label = gtk::Label::new(None);
    detail_label.set_xalign(0.0);
    detail_label.set_yalign(0.0);
    detail_label.set_selectable(true);
    detail_label.set_wrap(true);
    detail_label.add_css_class("monospace");

    let status_box = gtk::Box::new(Orientation::Vertical, 10);
    status_box.set_margin_top(12);
    status_box.set_margin_bottom(12);
    status_box.set_margin_start(12);
    status_box.set_margin_end(12);
    status_box.append(&state_row);
    status_box.append(&detail_label);

    let status_frame = gtk::Frame::new(Some("Status"));
    status_frame.set_child(Some(&status_box));
    // Size to its contents. Without this the two panels split the column evenly
    // and the circuit list - which grows - is squeezed by a panel that does not.
    status_frame.set_vexpand(false);
    status_frame.set_valign(gtk::Align::Start);

    // --- bottom left: circuits ---------------------------------------------
    let circuit_list = gtk::Box::new(Orientation::Vertical, 6);
    circuit_list.set_margin_top(12);
    circuit_list.set_margin_bottom(12);
    circuit_list.set_margin_start(12);
    circuit_list.set_margin_end(12);

    let circuit_scroll = gtk::ScrolledWindow::new();
    circuit_scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    circuit_scroll.set_child(Some(&circuit_list));
    circuit_scroll.set_vexpand(true);

    let circuit_frame = gtk::Frame::new(Some("Circuits"));
    circuit_frame.set_child(Some(&circuit_scroll));
    circuit_frame.set_vexpand(true);

    let left = gtk::Box::new(Orientation::Vertical, 12);
    left.set_margin_top(12);
    left.set_margin_bottom(12);
    left.set_margin_start(12);
    left.append(&status_frame);
    left.append(&circuit_frame);
    // Enough for the longest status line and no more; the map takes the rest.
    left.set_size_request(340, -1);

    // --- right: the map -----------------------------------------------------
    // Circuits are shared with the draw function, which runs on the main loop
    // and so cannot race with the update that replaces them.
    let drawn_circuits: Rc<RefCell<Vec<Circuit>>> = Rc::new(RefCell::new(Vec::new()));

    // 1.0 means "fit the circuits exactly"; larger magnifies about that centre.
    let zoom = Rc::new(RefCell::new(1.0_f64));

    let map_area = gtk::DrawingArea::new();
    map_area.set_hexpand(true);
    map_area.set_vexpand(true);
    {
        let drawn = drawn_circuits.clone();
        let zoom = zoom.clone();
        map_area.set_draw_func(move |area, cr, width, height| {
            draw_map(area, cr, width, height, &drawn.borrow(), *zoom.borrow());
        });
    }

    let zoom_in = gtk::Button::from_icon_name("zoom-in-symbolic");
    let zoom_out = gtk::Button::from_icon_name("zoom-out-symbolic");
    let zoom_fit = gtk::Button::from_icon_name("zoom-fit-best-symbolic");
    zoom_in.set_tooltip_text(Some("Zoom in  (+)"));
    zoom_out.set_tooltip_text(Some("Zoom out  (−)"));
    zoom_fit.set_tooltip_text(Some("Fit the circuits  (0)"));

    let zoom_box = gtk::Box::new(Orientation::Horizontal, 0);
    zoom_box.add_css_class("linked");
    zoom_box.append(&zoom_out);
    zoom_box.append(&zoom_fit);
    zoom_box.append(&zoom_in);
    zoom_box.set_halign(gtk::Align::End);
    zoom_box.set_valign(gtk::Align::End);
    zoom_box.set_margin_end(12);
    zoom_box.set_margin_bottom(12);

    let map_overlay = gtk::Overlay::new();
    map_overlay.set_child(Some(&map_area));
    map_overlay.add_overlay(&zoom_box);

    let map_frame = gtk::Frame::new(Some("Route map"));
    map_frame.set_child(Some(&map_overlay));
    map_frame.set_hexpand(true);
    map_frame.set_vexpand(true);
    map_frame.set_margin_top(12);
    map_frame.set_margin_bottom(12);
    map_frame.set_margin_end(12);
    map_frame.set_margin_start(12);

    let panes = gtk::Paned::new(Orientation::Horizontal);
    panes.set_start_child(Some(&left));
    panes.set_end_child(Some(&map_frame));
    panes.set_position(340);
    // Growing the window grows the map. The status and circuit panels have a
    // natural width and gain nothing from more of it.
    panes.set_resize_start_child(false);
    panes.set_resize_end_child(true);
    panes.set_shrink_start_child(false);

    // --- activity line ------------------------------------------------------
    let activity = gtk::Label::new(Some("Connecting to the tort daemon…"));
    activity.set_xalign(0.0);
    activity.add_css_class("dim-label");
    activity.set_margin_start(14);
    activity.set_margin_bottom(8);

    let spinner = gtk::Spinner::new();
    let activity_row = gtk::Box::new(Orientation::Horizontal, 8);
    activity_row.append(&spinner);
    activity_row.append(&activity);
    activity_row.set_margin_start(10);
    activity_row.set_margin_bottom(6);

    let root = gtk::Box::new(Orientation::Vertical, 0);
    root.append(&panes);
    root.append(&activity_row);

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Tor Traffic Tunnel")
        .default_width(1100)
        .default_height(700)
        .child(&root)
        .build();
    window.set_titlebar(Some(&header));

    // Tracks whether the tunnel is up, so the one button can be Connect or
    // Disconnect without asking the daemon what it should say.
    let is_up = Rc::new(RefCell::new(false));

    // --- wiring -------------------------------------------------------------
    {
        let sender = sender.clone();
        let is_up = is_up.clone();
        connect_button.connect_clicked(move |_| {
            let request = if *is_up.borrow() { Request::Down } else { Request::Up };
            spawn_request(sender.clone(), request);
        });
    }

    shell_button.connect_clicked(|_| {
        // Launch a terminal running `tort shell` rather than proxying a shell
        // through the GUI: a terminal emulator is already very good at being a
        // terminal, and tort inherits its stdio naturally.
        launch_in_terminal(&["tort", "shell"]);
    });

    {
        let window = window.clone();
        app_button.connect_clicked(move |_| prompt_for_command(&window));
    }

    // Receive worker results on the main loop.
    {
        let indicator = indicator.clone();
        let state_label = state_label.clone();
        let detail_label = detail_label.clone();
        let progress_label = progress_label.clone();
        let circuit_list = circuit_list.clone();
        let map_area = map_area.clone();
        let drawn_circuits = drawn_circuits.clone();
        let zoom = zoom.clone();
        let connect_button = connect_button.clone();
        let activity = activity.clone();
        let spinner = spinner.clone();
        let is_up = is_up.clone();

        glib::spawn_future_local(async move {
            while let Ok(update) = receiver.recv().await {
                match update {
                    Update::Status(report) => {
                        *is_up.borrow_mut() = report.is_up();
                        apply_status(&indicator, &state_label, &detail_label, &connect_button, &report);

                        // Circuits belong to a running tor. Once it is gone they
                        // are history, and a map still showing them would be
                        // claiming something that is no longer true. The route
                        // poll cannot do this itself: it fails while tort is
                        // down and returns nothing, so the last good answer
                        // would linger indefinitely.
                        if !report.is_up() && !drawn_circuits.borrow().is_empty() {
                            drawn_circuits.borrow_mut().clear();
                            show_circuits(&circuit_list, &[]);
                            *zoom.borrow_mut() = 1.0;
                            map_area.queue_draw();
                        }
                    }
                    Update::Progress(line) => {
                        progress_label.set_text(&line);
                        progress_label.set_visible(true);
                    }
                    Update::Circuits(circuits) => {
                        show_circuits(&circuit_list, &circuits);
                        *drawn_circuits.borrow_mut() = circuits;
                        map_area.queue_draw();
                    }
                    Update::Done(text) => activity.set_text(&text),
                    Update::Failed(message) => {
                        activity.set_text(&format!("Failed: {message}"));
                    }
                    Update::Denied(message) => {
                        activity.set_text(&format!("Not authorized: {message}"));
                    }
                    Update::Busy(busy) => {
                        if busy {
                            spinner.start();
                        } else {
                            spinner.stop();
                            // Progress describes work in flight; leaving the
                            // last line up afterwards would suggest it is still
                            // happening.
                            progress_label.set_visible(false);
                        }
                        connect_button.set_sensitive(!busy);
                    }
                }
            }
        });
    }

    // --- zoom ---------------------------------------------------------------
    let apply_zoom = {
        let zoom = zoom.clone();
        let map_area = map_area.clone();
        move |factor: f64| {
            let mut z = zoom.borrow_mut();
            // Clamped so the view cannot be zoomed into meaninglessness, or out
            // so far the world becomes a dot.
            *z = (*z * factor).clamp(0.4, 20.0);
            drop(z);
            map_area.queue_draw();
        }
    };

    {
        let apply = apply_zoom.clone();
        zoom_in.connect_clicked(move |_| apply(1.4));
    }
    {
        let apply = apply_zoom.clone();
        zoom_out.connect_clicked(move |_| apply(1.0 / 1.4));
    }
    {
        let zoom = zoom.clone();
        let map_area = map_area.clone();
        zoom_fit.connect_clicked(move |_| {
            *zoom.borrow_mut() = 1.0;
            map_area.queue_draw();
        });
    }

    // Keyboard: + and - to zoom, 0 to fit. Accepts the shifted and keypad forms
    // too, since "+" is shift-equals on most layouts and nobody wants to think
    // about that.
    {
        let apply = apply_zoom.clone();
        let zoom = zoom.clone();
        let map_area = map_area.clone();
        let keys = gtk::EventControllerKey::new();
        keys.connect_key_pressed(move |_, key, _, _| {
            use gtk::gdk::Key;
            match key {
                Key::plus | Key::equal | Key::KP_Add => apply(1.4),
                Key::minus | Key::underscore | Key::KP_Subtract => apply(1.0 / 1.4),
                Key::_0 | Key::KP_0 => {
                    *zoom.borrow_mut() = 1.0;
                    map_area.queue_draw();
                }
                _ => return glib::Propagation::Proceed,
            }
            glib::Propagation::Stop
        });
        window.add_controller(keys);
    }

    // Scrolling over the map zooms it, which is what everyone tries first.
    {
        let apply = apply_zoom.clone();
        let scroll = gtk::EventControllerScroll::new(gtk::EventControllerScrollFlags::VERTICAL);
        scroll.connect_scroll(move |_, _, dy| {
            apply(if dy < 0.0 { 1.15 } else { 1.0 / 1.15 });
            glib::Propagation::Stop
        });
        map_area.add_controller(scroll);
    }

    // Poll for status and circuits.
    refresh(sender.clone());
    glib::timeout_add_seconds_local(REFRESH_SECONDS, move || {
        refresh(sender.clone());
        glib::ControlFlow::Continue
    });

    window.present();
}

/// Ask the daemon for status and circuits, without blocking the main loop.
fn refresh(sender: async_channel::Sender<Update>) {
    spawn_query(sender.clone(), Request::Status);
    spawn_query(sender, Request::Route);
}

/// A read-only query: no busy state, no activity text on success.
fn spawn_query(sender: async_channel::Sender<Update>, request: Request) {
    std::thread::spawn(move || {
        // Not interactive. A poll must never raise an authentication dialog:
        // one appearing out of nowhere seconds after an unrelated action is
        // baffling, and while it waited for an answer the daemon would be held
        // and everything the user actually asked for would queue behind it.
        let update = match send(&request, None, false) {
            Ok(Response::Status(report)) => Update::Status(Box::new(report)),
            Ok(Response::Circuits { circuits }) => Update::Circuits(circuits),
            // A refused or failed poll is not worth interrupting the user over;
            // `route` in particular is denied until they authenticate, and
            // nagging every ten seconds would be worse than saying nothing.
            _ => return,
        };
        let _ = sender.send_blocking(update);
    });
}

/// A state-changing request: shows progress and reports the outcome.
fn spawn_request(sender: async_channel::Sender<Update>, request: Request) {
    let label = match request {
        Request::Up => "Connecting…",
        Request::Down => "Disconnecting…",
        _ => "Working…",
    };
    let _ = sender.send_blocking(Update::Busy(true));
    let _ = sender.send_blocking(Update::Done(label.to_string()));

    std::thread::spawn(move || {
        // The daemon reports progress by writing to the stdout its caller lends
        // it - which is how the CLI shows tor bootstrapping. A GUI has no stdout
        // worth lending, so it lends a pipe and reads the other end. Same
        // mechanism, no special case in the daemon.
        let pipe = nix::unistd::pipe().ok();
        let progress_writer = pipe.as_ref().map(|(_, w)| w.as_raw_fd());

        if let Some((reader, _)) = pipe.as_ref() {
            let sender = sender.clone();
            let reader = reader.try_clone().ok();
            if let Some(reader) = reader {
                std::thread::spawn(move || {
                    let lines = BufReader::new(std::fs::File::from(reader)).lines();
                    for line in lines.map_while(Result::ok) {
                        let line = line.trim().to_string();
                        if !line.is_empty() {
                            let _ = sender.send_blocking(Update::Progress(line));
                        }
                    }
                });
            }
        }

        let devnull = std::fs::File::open("/dev/null").ok();
        let stdio = match (&devnull, progress_writer) {
            (Some(null), Some(w)) => Some([null.as_raw_fd(), w, w]),
            _ => None,
        };

        // Interactive: the user clicked something and is waiting, so polkit may
        // ask them for a password.
        let outcome = send(&request, stdio, true);

        // Close our copy of the write end so the reader thread sees EOF and
        // stops, rather than lingering for the life of the application.
        drop(pipe);

        let update = match outcome {
            Ok(Response::Ok { output }) => {
                Update::Done(output.lines().next().unwrap_or("Done").to_string())
            }
            Ok(Response::Failed { message }) => Update::Failed(message),
            Ok(Response::Denied { message }) => Update::Denied(message),
            Ok(_) => Update::Done("Done".into()),
            Err(e) => Update::Failed(format!("{e:#}")),
        };
        let _ = sender.send_blocking(update);
        let _ = sender.send_blocking(Update::Busy(false));
        // Reflect the new state immediately rather than waiting for the timer.
        spawn_query(sender.clone(), Request::Status);
        spawn_query(sender, Request::Route);
    });
}

fn send(request: &Request, stdio: Option<[RawFd; 3]>, interactive: bool) -> anyhow::Result<Response> {
    let stream = tort::client::connect()
        .ok_or_else(|| anyhow::anyhow!("the tort daemon is not running (systemctl start tortd)"))?;
    tort::client::send(&stream, request, stdio, interactive)
}

fn apply_status(
    indicator: &gtk::Label,
    state: &gtk::Label,
    detail: &gtk::Label,
    button: &gtk::Button,
    report: &StatusReport,
) {
    use tort::verify::Verdict;

    let confirmed = report
        .check
        .as_ref()
        .map(|c| c.verdict == Verdict::ThroughTor)
        .unwrap_or(false);

    // Three states, not two. "Up but unverified" is its own thing and must not
    // be shown as protected: the whole design rests on not claiming what has
    // not been measured.
    let (colour, text) = if report.is_partial() {
        ("#e6a23c", "Partial — run Disconnect to clean up")
    } else if confirmed {
        ("#7fbf7f", "Connected — traffic confirmed through Tor")
    } else if report.is_up() {
        ("#e6a23c", "Up, but not verified")
    } else {
        ("#888888", "Disconnected")
    };

    indicator.set_markup(&format!("<span foreground=\"{colour}\">●</span>"));
    state.set_text(text);
    button.set_label(if report.is_up() { "Disconnect" } else { "Connect" });

    let mut lines = vec![
        mark(report.namespace, "namespace"),
        mark(report.rules, "firewall rules"),
        mark(report.tor, "tor"),
    ];

    if let Some(exit) = report.check.as_ref().and_then(|c| c.exit.as_ref()) {
        lines.push(String::new());
        // These strings come from a third-party API response and are rendered as
        // Pango markup, so they are escaped rather than trusted.
        let esc = |t: &str| glib::markup_escape_text(t).to_string();
        if let Some(ip) = &exit.ip {
            lines.push(format!("exit node   {}", esc(ip)));
        }
        let place: Vec<&str> = [&exit.city, &exit.region, &exit.country]
            .into_iter()
            .filter_map(|f| f.as_deref())
            .filter(|f| !f.is_empty())
            .collect();
        if !place.is_empty() {
            lines.push(format!("location    {}", esc(&place.join(", "))));
        }
        if let Some(org) = &exit.org {
            lines.push(format!("operator    {}", esc(org)));
        }
    }

    detail.set_markup(&lines.join("\n"));
}

/// A tick or a cross, coloured, with the thing it refers to.
///
/// Colour is never the only signal: the glyph differs too, so the display works
/// without colour vision and survives being pasted somewhere as plain text.
fn mark(present: bool, label: &str) -> String {
    if present {
        format!("<span foreground=\"#7fbf7f\">✓</span>  {label}")
    } else {
        format!("<span foreground=\"#888888\">✗</span>  {label}")
    }
}

fn show_circuits(list: &gtk::Box, circuits: &[Circuit]) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    let general: Vec<&Circuit> = circuits
        .iter()
        .filter(|c| c.purpose == "GENERAL" && c.state == "BUILT")
        .collect();

    if general.is_empty() {
        let empty = gtk::Label::new(Some("No circuits carrying traffic yet."));
        empty.add_css_class("dim-label");
        empty.set_xalign(0.0);
        list.append(&empty);
        return;
    }

    for (index, circuit) in general.iter().enumerate() {
        let colour = CIRCUIT_COLOURS[index % CIRCUIT_COLOURS.len()];

        let swatch = gtk::Label::new(None);
        swatch.set_markup(&format!("<span foreground=\"{colour}\">█</span>"));

        // The circuit number accompanies the colour everywhere, so the display
        // still works without colour vision.
        let heading = gtk::Label::new(None);
        heading.set_markup(&format!("<b>circuit {}</b>", circuit.id));
        heading.set_xalign(0.0);

        let heading_row = gtk::Box::new(Orientation::Horizontal, 8);
        heading_row.append(&swatch);
        heading_row.append(&heading);

        let hops = gtk::Label::new(Some(&describe_hops(circuit)));
        hops.set_xalign(0.0);
        hops.add_css_class("monospace");
        hops.add_css_class("dim-label");

        let row = gtk::Box::new(Orientation::Vertical, 2);
        row.append(&heading_row);
        row.append(&hops);
        list.append(&row);
    }
}

fn describe_hops(circuit: &Circuit) -> String {
    let last = circuit.hops.len().saturating_sub(1);
    circuit
        .hops
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let role = match i {
                0 => "guard ",
                n if n == last => "exit  ",
                _ => "middle",
            };
            let country = hop.country.as_deref().unwrap_or("--");
            format!("  {role} {:<18} {country}", hop.nickname)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Ask for a command, then run it inside the tunnel.
fn prompt_for_command(parent: &ApplicationWindow) {
    let entry = gtk::Entry::new();
    entry.set_placeholder_text(Some("firefox --profile /tmp/tort-firefox"));
    entry.set_activates_default(true);
    entry.set_hexpand(true);

    let hint = gtk::Label::new(Some(
        "Launch a browser with its own profile directory. Started a second time \
         against\nan existing profile, a browser hands the request to the running \
         instance —\nwhich is outside the tunnel.",
    ));
    hint.set_xalign(0.0);
    hint.add_css_class("dim-label");

    let content = gtk::Box::new(Orientation::Vertical, 10);
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);
    content.append(&entry);
    content.append(&hint);

    let dialog = gtk::Dialog::builder()
        .transient_for(parent)
        .modal(true)
        .title("Run inside the tunnel")
        .build();
    dialog.content_area().append(&content);
    dialog.add_button("Cancel", gtk::ResponseType::Cancel);
    let run = dialog.add_button("Run", gtk::ResponseType::Accept);
    run.add_css_class("suggested-action");
    dialog.set_default_response(gtk::ResponseType::Accept);

    dialog.connect_response(move |dialog, response| {
        if response == gtk::ResponseType::Accept {
            let command = entry.text().to_string();
            if !command.trim().is_empty() {
                spawn_detached(&format!("tort run {command}"));
            }
        }
        dialog.close();
    });

    dialog.present();
}

/// Run a command in the user's terminal.
///
/// Finding "the default terminal" on Linux has no single answer, so the sources
/// are consulted in order of how authoritative they are about the user's
/// *choice* rather than what happens to be installed. An earlier version simply
/// took the first terminal it found on disk, which is not the same question: a
/// machine with three terminals installed has one the user actually wants.
fn launch_in_terminal(command: &[&str]) {
    let Some((program, prefix)) = terminal_launcher() else {
        eprintln!("tortunnel: no terminal emulator found");
        return;
    };

    // Built as an argument vector rather than a shell string: nothing here needs
    // a shell, and a shell would mean worrying about quoting.
    let _ = std::process::Command::new(&program)
        .args(&prefix)
        .args(command)
        .spawn();
}

/// The terminal to use, and the arguments that precede the command.
fn terminal_launcher() -> Option<(String, Vec<String>)> {
    // 1. $TERMINAL. An explicit statement of preference, so it wins.
    if let Ok(terminal) = std::env::var("TERMINAL") {
        if !terminal.is_empty() && which(&terminal) {
            return Some((terminal.clone(), launch_prefix(&terminal)));
        }
    }

    // 2. xdg-terminal-exec, the freedesktop tool that exists to answer exactly
    //    this question. It takes the command directly, with no -e to guess at.
    if which("xdg-terminal-exec") {
        return Some(("xdg-terminal-exec".into(), Vec::new()));
    }

    // 3. The desktop's configured default.
    if let Some(terminal) = gnome_default_terminal() {
        if which(&terminal) {
            return Some((terminal.clone(), launch_prefix(&terminal)));
        }
    }

    // 4. Debian's alternatives system.
    if which("x-terminal-emulator") {
        return Some(("x-terminal-emulator".into(), vec!["-e".into()]));
    }

    // 5. Last resort: something, anything, that is installed.
    ["ghostty", "alacritty", "foot", "kitty", "wezterm", "konsole", "gnome-terminal", "xterm"]
        .into_iter()
        .find(|t| which(t))
        .map(|t| (t.to_string(), launch_prefix(t)))
}

/// The arguments a given terminal wants before the command it should run.
///
/// There is no convention here worth relying on: some take the command bare,
/// some want `-e`, some `--`. Guessing wrong opens an empty terminal, which
/// looks like the feature is broken rather than mis-invoked.
fn launch_prefix(terminal: &str) -> Vec<String> {
    let name = std::path::Path::new(terminal)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(terminal);

    match name {
        "xdg-terminal-exec" | "kitty" | "foot" => Vec::new(),
        "wezterm" => vec!["start".into(), "--".into()],
        "gnome-terminal" | "tilix" | "blackbox" => vec!["--".into()],
        _ => vec!["-e".into()],
    }
}

fn gnome_default_terminal() -> Option<String> {
    let output = std::process::Command::new("gsettings")
        .args(["get", "org.gnome.desktop.default-applications.terminal", "exec"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout)
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_string();
    (!value.is_empty()).then_some(value)
}

/// Is this program runnable - either an absolute path, or on PATH?
fn which(program: &str) -> bool {
    if program.contains('/') {
        return std::path::Path::new(program).is_file();
    }
    std::process::Command::new("which")
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Start a command and do not wait for it.
///
/// Deliberately via the `tort` CLI rather than by talking to the daemon here:
/// the CLI already lends the daemon its terminal, drops to the calling user and
/// performs the browser-handoff check, none of which should be reimplemented.
fn spawn_detached(command: &str) {
    let _ = std::process::Command::new("sh").arg("-c").arg(command).spawn();
}

/// Paint the world and the circuit paths over it.
///
/// The view frames the circuits rather than the globe: once relays are known the
/// map fits their bounding box, so the interesting part fills the pane instead
/// of being three dots on a world map. With no circuits it falls back to the
/// whole world.
///
/// Colours are read from the widget's style context, so the map follows the
/// desktop's light or dark theme rather than being a pale rectangle in a dark
/// window.
fn draw_map(
    area: &gtk::DrawingArea,
    cr: &gtk::cairo::Context,
    width: i32,
    height: i32,
    circuits: &[Circuit],
    zoom: f64,
) {
    use tort::map::{world, Bounds, Projection};

    let (w, h) = (width as f64, height as f64);
    let world = world();

    let general: Vec<&Circuit> = circuits
        .iter()
        .filter(|c| c.purpose == "GENERAL" && c.state == "BUILT")
        .collect();

    // Every located hop of every circuit, which is what the view should frame.
    let located: Vec<[f64; 2]> = general
        .iter()
        .flat_map(|c| c.hops.iter())
        .filter_map(|hop| hop.country.as_deref())
        .filter_map(|c| world.locate(c))
        .collect();

    let bounds = Bounds::around(&located)
        // A generous margin, and a floor of 40 degrees: relays in one country
        // should still be shown in a recognisable part of the world.
        .map(|b| b.padded(0.45, 40.0))
        .unwrap_or_else(Bounds::world);

    let projection = Projection::new(&bounds, w, h, zoom);

    let fg = area.style_context().color();
    let dim = |alpha: f64| (fg.red() as f64, fg.green() as f64, fg.blue() as f64, alpha);

    // Does this ring cross the edge of the view? Consecutive points then land on
    // opposite sides, which draws as a streak straight across the map.
    let wraps = |ring: &[[f64; 2]]| {
        ring.windows(2).any(|pair| {
            (projection.wrap(pair[1][0]) - projection.wrap(pair[0][0])).abs() > 180.0
        })
    };

    // Land, shaded, so the eye can tell coast from sea without tracing outlines.
    //
    // Every ring goes into one path filled with the even-odd rule, which is what
    // makes holes work: the dataset gives inner rings - the Caspian, Lesotho -
    // alongside the outer ones, and even-odd punches them out rather than
    // filling them twice. Rings that cross the view edge are left out, because
    // filling a broken ring closes it with a straight line across the map.
    let (r, g, b, a) = dim(0.10);
    cr.set_source_rgba(r, g, b, a);
    cr.set_fill_rule(gtk::cairo::FillRule::EvenOdd);
    for ring in &world.rings {
        if wraps(ring) {
            continue;
        }
        let mut points = ring.iter();
        if let Some(first) = points.next() {
            let (x, y) = projection.project(first[0], first[1]);
            cr.move_to(x, y);
            for point in points {
                let (x, y) = projection.project(point[0], point[1]);
                cr.line_to(x, y);
            }
            cr.close_path();
        }
    }
    let _ = cr.fill();

    // Coastlines over the shading: they are a backdrop for the paths, not the
    // subject, so they stay faint.
    let (r, g, b, a) = dim(0.30);
    cr.set_source_rgba(r, g, b, a);
    cr.set_line_width(0.7);
    for ring in &world.rings {
        let mut started = false;
        let mut previous_lon = 0.0_f64;

        for point in ring {
            let (lon, lat) = (point[0], point[1]);
            let (x, y) = projection.project(lon, lat);
            let wrapped =
                started && (projection.wrap(lon) - projection.wrap(previous_lon)).abs() > 180.0;

            if !started || wrapped {
                cr.move_to(x, y);
                started = true;
            } else {
                cr.line_to(x, y);
            }
            previous_lon = lon;
        }
    }
    let _ = cr.stroke();

    if general.is_empty() {
        let (r, g, b, a) = dim(0.5);
        cr.set_source_rgba(r, g, b, a);
        cr.select_font_face("sans", gtk::cairo::FontSlant::Normal, gtk::cairo::FontWeight::Normal);
        cr.set_font_size(13.0);
        cr.move_to(16.0, h - 16.0);
        let _ = cr.show_text("No circuits carrying traffic yet.");
        return;
    }

    for (index, circuit) in general.iter().enumerate() {
        let (r, g, b) = circuit_rgb(index);

        // Hops whose country tor could not resolve are skipped rather than
        // guessed at: a line to the wrong continent is worse than a gap.
        let points: Vec<(f64, f64)> = circuit
            .hops
            .iter()
            .filter_map(|hop| hop.country.as_deref())
            .filter_map(|c| world.locate(c))
            .map(|[lon, lat]| projection.project(lon, lat))
            .collect();

        if points.len() < 2 {
            continue;
        }

        // The path.
        cr.set_source_rgba(r, g, b, 0.85);
        cr.set_line_width(1.8);
        cr.set_line_join(gtk::cairo::LineJoin::Round);
        cr.move_to(points[0].0, points[0].1);
        for point in &points[1..] {
            cr.line_to(point.0, point.1);
        }
        let _ = cr.stroke();

        // Hops. The exit is drawn larger and haloed, because it is the one the
        // outside world sees and the one the status panel names.
        let last = points.len() - 1;
        for (i, (x, y)) in points.iter().enumerate() {
            let radius = if i == last { 5.0 } else { 3.0 };
            cr.set_source_rgba(r, g, b, 1.0);
            cr.arc(*x, *y, radius, 0.0, std::f64::consts::TAU);
            let _ = cr.fill();

            if i == last {
                cr.set_source_rgba(r, g, b, 0.35);
                cr.arc(*x, *y, radius + 4.0, 0.0, std::f64::consts::TAU);
                let _ = cr.fill();
            }
        }
    }
}

/// The circuit palette as floating-point RGB, parsed from the same hex strings
/// the list uses so the two can never disagree.
fn circuit_rgb(index: usize) -> (f64, f64, f64) {
    let hex = CIRCUIT_COLOURS[index % CIRCUIT_COLOURS.len()];
    let component = |from: usize| {
        u8::from_str_radix(&hex[from..from + 2], 16).unwrap_or(128) as f64 / 255.0
    };
    (component(1), component(3), component(5))
}
