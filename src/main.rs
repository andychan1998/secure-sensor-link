//! Runs the receiver on stdin and stdout.

use std::io;
use std::process::ExitCode;

use secure_sensor_link::input::ErasingReader;

fn main() -> ExitCode {
    // Read through a buffer that is erased as it goes, so key text from the
    // input doesn't stay in the standard library's stdin buffer.
    let input = ErasingReader::new(io::stdin().lock());
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
