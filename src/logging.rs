use colored::*;
use reqwest::blocking::Client;
use std::sync::Mutex;

pub enum LogColor {
    Red,
    Green,
    Blue,
    Yellow,
    Cyan,
    Magenta,
    White,
    Black,
}

pub struct Logger {
    http_endpoint: Option<String>,
    client: Client,
}

impl Logger {
    pub fn new(http_endpoint: Option<String>) -> Self {
        Logger {
            http_endpoint,
            client: Client::new(),
        }
    }

    pub fn log_info(&self, message: &str) {
        self.log_color(message, LogColor::Blue);
    }

    pub fn log_warning(&self, message: &str) {
        self.log_color(message, LogColor::Yellow);
    }

    pub fn log_error(&self, message: &str) {
        self.log_color(message, LogColor::Red);
    }

    pub fn log_success(&self, message: &str) {
        self.log_color(message, LogColor::Green);
    }

    pub fn log_color(&self, message: &str, color: LogColor) {
        let colored_message = match color {
            LogColor::Red => message.red(),
            LogColor::Green => message.green(),
            LogColor::Blue => message.blue(),
            LogColor::Yellow => message.yellow(),
            LogColor::Cyan => message.cyan(),
            LogColor::Magenta => message.magenta(),
            LogColor::White => message.white(),
            LogColor::Black => message.black(),
        };
        println!("{}", colored_message);

        if let Some(ref endpoint) = self.http_endpoint {
            let _ = self.client.post(endpoint).body(message.to_string()).send();
        }
    }
}
