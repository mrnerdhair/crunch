use rustls::KeyLog;

#[derive(Debug, Default)]
pub struct PrintLnKeyLog;

impl KeyLog for PrintLnKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        println!("{}\t{}\t{}", label, hex::encode(client_random), hex::encode(secret));
    }
}
