use std::{fmt::Debug, sync::{atomic::AtomicU64, Arc, RwLock}};

enum HashReporterState {
    Unreported(Option<Box<dyn FnOnce([u8; 32]) + Send + Sync + 'static>>),
    Reported([u8; 32]),
}

impl std::fmt::Debug for HashReporterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreported(arg0) => f.debug_tuple("Unreported").field(if arg0.is_some() { &Some(()) } else { &None::<()> }).finish(),
            Self::Reported(arg0) => f.debug_tuple("Reported").field(&hex::encode(arg0)).finish(),
        }
    }
}

impl Default for HashReporterState {
    fn default() -> Self {
        Self::Unreported(None)
    }
}

#[derive(Default)]
pub struct HashReporter(Arc<RwLock<HashReporterState>>);

impl HashReporter {
    pub fn new<T: FnOnce([u8; 32]) + Send + Sync + 'static>(f: T) -> Self {
        Self(Arc::new(RwLock::new(HashReporterState::Unreported(Some(Box::new(f))))))
    }

    pub fn reported(&self) -> bool {
        self.as_reported().is_some()
    }

    pub fn as_reported(&self) -> Option<[u8; 32]> {
        match *self.0.read().unwrap() {
            HashReporterState::Unreported(_) => None,
            HashReporterState::Reported(x) => Some(x),
        }
    }

    pub fn report(&self, transcript_hash: [u8; 32]) {
        let mut x = self.0.write().unwrap();
        match core::mem::replace(&mut *x, HashReporterState::Reported(transcript_hash)) {
            HashReporterState::Reported(old_hash) => assert_eq!(transcript_hash, old_hash, "new hash reported ({}) doesn't match old one ({})", hex::encode(transcript_hash), hex::encode(old_hash)),
            HashReporterState::Unreported(Some(f)) => f(transcript_hash),
            _ => (),
        }
    }
}

impl Clone for HashReporter {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Debug for HashReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HashReporter").field(&self.0.read().unwrap()).finish()
    }
}

#[derive(Debug, Default, Clone)]
pub struct HashReporters {
    next_count: Arc<AtomicU64>,
    ch_sh_transcript_hash_reporter: HashReporter,
    ch_sf_transcript_hash_reporter: HashReporter,
}

impl HashReporters {
    pub fn new(ch_sh_transcript_hash_reporter: HashReporter, ch_sf_transcript_hash_reporter: HashReporter) -> Self {
        let out = Self {
            next_count: Arc::new(AtomicU64::new(0)),
            ch_sh_transcript_hash_reporter,
            ch_sf_transcript_hash_reporter,
        };
        out
    }

    pub fn next(&self) -> HashReporter {
        match self.next_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) {
            0 => self.ch_sh_transcript_hash_reporter.clone(),
            3 => self.ch_sf_transcript_hash_reporter.clone(),
            _ => HashReporter::default(),
        }
    }

    pub fn report(&self, x: [u8; 32]) {
        let foo = self.next();
        foo.report(x);
    }

    pub fn report_ch_sh_transcript_hash(&self, x: [u8; 32]) {
        self.ch_sh_transcript_hash_reporter.report(x);
    }

    pub fn report_ch_sf_transcript_hash(&self, x: [u8; 32]) {
        self.ch_sf_transcript_hash_reporter.report(x);
    }
}
