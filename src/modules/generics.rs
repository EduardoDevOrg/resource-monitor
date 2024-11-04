use std::io::Write;
use serde_json::ser::Formatter;
pub struct CustomFormatter;

impl Formatter for CustomFormatter {
    fn write_f64<W>(&mut self, writer: &mut W, value: f64) -> std::io::Result<()>
    where
        W: Write + ?Sized,
    {
        write!(writer, "{:.3}", value)
    }
}

