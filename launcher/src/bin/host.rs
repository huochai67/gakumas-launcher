#![cfg_attr(windows, windows_subsystem = "windows")]

#[path = "../host.rs"]
mod host;

fn main() {
    host::run_and_exit();
}
