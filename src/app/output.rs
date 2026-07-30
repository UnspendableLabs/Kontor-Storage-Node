//! The operator-facing output stream.
//!
//! Startup used to be one straight line of code holding one `&mut impl Write`,
//! and every step wrote its progress to it. It is now two: the part that runs
//! before the server starts, and the supervisor task that carries on afterwards,
//! activating the node whenever an operator gives it what it was missing. Both
//! narrate the same startup, so both need the same stream — and one of them
//! lives in a spawned task, which a borrowed writer cannot follow.
//!
//! Hence a handle that is `Clone + Send + 'static` and writes through to one
//! underlying sink. In production that sink is stdout; in tests it is a buffer
//! the test can read back.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};

/// A writer several tasks can share.
#[derive(Clone)]
pub struct SharedWriter {
    sink: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl SharedWriter {
    /// Write through to an arbitrary sink.
    #[must_use]
    pub fn new(sink: impl Write + Send + 'static) -> Self {
        Self {
            sink: Arc::new(Mutex::new(Box::new(sink))),
        }
    }

    /// The production sink.
    #[must_use]
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }

    /// A sink whose contents a test can read back.
    #[cfg(test)]
    #[must_use]
    pub fn buffer() -> (Self, Captured) {
        let captured = Captured::default();
        (Self::new(captured.clone()), captured)
    }
}

// A poisoned sink is recovered from rather than propagated: a panic elsewhere
// must not turn every subsequent log line into an error, least of all while the
// node is trying to explain what went wrong.
impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .flush()
    }
}

/// Everything written to a [`SharedWriter::buffer`], readable at any point.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct Captured {
    bytes: Arc<Mutex<Vec<u8>>>,
}

#[cfg(test)]
impl Captured {
    /// Everything written so far, as text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .bytes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .into_owned()
    }

    /// Wait until the output contains `needle`, or give up.
    ///
    /// The supervisor runs concurrently with the test, so "has the node said X
    /// yet" is a question with a timing answer. Polling beats sleeping a fixed
    /// interval: it returns as soon as the line appears and only spends the full
    /// budget on an actual failure.
    pub async fn wait_for(&self, needle: &str, within: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            if self.text().contains(needle) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.text().contains(needle)
    }
}

#[cfg(test)]
impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_from_every_clone_land_in_one_place() {
        let (writer, captured) = SharedWriter::buffer();

        let mut first = writer.clone();
        let mut second = writer;
        write!(first, "one ").unwrap();
        write!(second, "two").unwrap();
        first.flush().unwrap();

        assert_eq!(captured.text(), "one two");
    }

    #[tokio::test]
    async fn wait_for_returns_as_soon_as_the_line_appears() {
        let (mut writer, captured) = SharedWriter::buffer();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            writeln!(writer, "the line").unwrap();
        });

        assert!(
            captured
                .wait_for("the line", std::time::Duration::from_secs(2))
                .await
        );
    }

    #[tokio::test]
    async fn wait_for_gives_up_on_a_line_that_never_comes() {
        let (_writer, captured) = SharedWriter::buffer();

        assert!(
            !captured
                .wait_for("never", std::time::Duration::from_millis(50))
                .await
        );
    }

    #[test]
    fn a_poisoned_sink_still_accepts_writes() {
        let (writer, captured) = SharedWriter::buffer();

        let poisoner = writer.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.sink.lock().unwrap();
            panic!("while holding the sink");
        }));

        let mut writer = writer;
        write!(writer, "after the panic").unwrap();
        assert_eq!(captured.text(), "after the panic");
    }
}
