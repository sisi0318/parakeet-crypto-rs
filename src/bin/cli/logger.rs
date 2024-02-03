pub struct CliLogger {
    module: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Level {
    Error,
    Info,
    Warn,
    Debug,
}

#[allow(dead_code)]
impl CliLogger {
    pub fn new<S: AsRef<str>>(module: S) -> Self {
        Self {
            module: format!("{:>5}", module.as_ref()),
        }
    }

    pub fn log<S: AsRef<str>>(&self, level: Level, msg: S) {
        let level = format!("{:?}", level).to_uppercase();
        eprintln!("[{}][{:>5}] {}", self.module, level, msg.as_ref());
    }

    pub fn info<S: AsRef<str>>(&self, msg: S) {
        self.log(Level::Info, msg);
    }

    pub fn error<S: AsRef<str>>(&self, msg: S) {
        self.log(Level::Error, msg);
    }

    pub fn warn<S: AsRef<str>>(&self, msg: S) {
        self.log(Level::Warn, msg);
    }

    #[allow(unused_variables)]
    pub fn debug<S: AsRef<str>>(&self, msg: S) {
        #[cfg(debug_assertions)]
        self.log(Level::Debug, msg);
    }
}
