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
    left.set_size_request(420, -1);

    // --- right: map, deliberately empty for now -----------------------------
    let map_placeholder = gtk::Label::new(Some(
        "Map\n\nCircuit paths will be drawn here.\n\
         Relay locations come from tor's own GeoIP database,\n\
         so inspecting a circuit tells no third party your path.",
    ));
    map_placeholder.set_justify(gtk::Justification::Center);
    map_placeholder.add_css_class("dim-label");

    let map_frame = gtk::Frame::new(Some("Route map"));
    map_frame.set_child(Some(&map_placeholder));
    map_frame.set_hexpand(true);
    map_frame.set_vexpand(true);
    map_frame.set_margin_top(12);
    map_frame.set_margin_bottom(12);
    map_frame.set_margin_end(12);
    map_frame.set_margin_start(12);

    let panes = gtk::Paned::new(Orientation::Horizontal);
    panes.set_start_child(Some(&left));
    panes.set_end_child(Some(&map_frame));
    panes.set_position(440);

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
        spawn_detached(&terminal_command("tort shell"));
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
                    }
                    Update::Progress(line) => {
                        progress_label.set_text(&line);
                        progress_label.set_visible(true);
                    }
                    Update::Circuits(circuits) => show_circuits(&circuit_list, &circuits),
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
        let update = match send(&request, None) {
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

        let outcome = send(&request, stdio);

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

fn send(request: &Request, stdio: Option<[RawFd; 3]>) -> anyhow::Result<Response> {
    let stream = tort::client::connect()
        .ok_or_else(|| anyhow::anyhow!("the tort daemon is not running (systemctl start tortd)"))?;
    tort::client::send(&stream, request, stdio)
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

/// The user's terminal emulator, running a command.
fn terminal_command(inner: &str) -> String {
    for terminal in ["ghostty", "alacritty", "foot", "kitty", "xterm"] {
        if which(terminal) {
            return format!("{terminal} -e {inner}");
        }
    }
    inner.to_string()
}

fn which(program: &str) -> bool {
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
