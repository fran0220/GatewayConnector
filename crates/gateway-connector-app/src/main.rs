#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

fn main() {
    gateway_connector_app::gpui_app::run(&gateway_connector_backend::GENERIC_DISTRIBUTION);
}
