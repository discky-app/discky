//! Discky.app entry point: parses `--self-check` and starts the app.

fn main() {
    let self_check = std::env::args().skip(1).any(|a| a == "--self-check");
    discky_app::run(self_check);
}
