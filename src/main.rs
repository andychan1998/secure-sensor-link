//! Runs the receiver on stdin and stdout.

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let input = io::stdin().lock();
    let output = io::stdout().lock();
    match secure_sensor_link::protocol::run(input, output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Only an I/O failure (for example, stdout closed) ends the receiver.
            #[allow(clippy::print_stderr)]
            {
                eprintln!("secure-sensor-link: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
