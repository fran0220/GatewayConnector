#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

fn main() {
    let distribution = &gateway_connector_backend::GENERIC_DISTRIBUTION;
    let request = match gateway_connector_app::isolated::LaunchRequest::from_args(
        distribution,
        std::env::args_os().skip(1),
    ) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("GatewayConnector could not start: {error}");
            std::process::exit(2);
        }
    };
    gateway_connector_app::gpui_app::run_launch(distribution, request);
}
