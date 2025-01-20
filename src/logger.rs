use colored::*;
use reqwest::blocking::Client;
use serde::Serialize;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref LOGGER: Mutex<Logger> =
        Mutex::new(Logger::new(Some("http://localhost:8080/log".to_string())));
}

#[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn log_info(&self, message: &str) {
        self.log_color(message, LogColor::Blue);
    }

    #[allow(dead_code)]
    pub fn log_warning(&self, message: &str) {
        self.log_color(message, LogColor::Yellow);
    }

    #[allow(dead_code)]
    pub fn log_error(&self, message: &str) {
        self.log_color(message, LogColor::Red);
    }

    #[allow(dead_code)]
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
            let log_message = LogMessage {
                message: message.to_string(),
                color: match color {
                    LogColor::Red => "31".to_string(),
                    LogColor::Green => "32".to_string(),
                    LogColor::Blue => "34".to_string(),
                    LogColor::Yellow => "33".to_string(),
                    LogColor::Cyan => "36".to_string(),
                    LogColor::Magenta => "35".to_string(),
                    LogColor::White => "37".to_string(),
                    LogColor::Black => "30".to_string(),
                },
            };

            match self.client.post(endpoint).json(&log_message).send() {
                Ok(response) => {
                    if !response.status().is_success() {
                        eprintln!("Failed to send log: {}", response.status());
                    }
                }
                Err(err) => {
                    eprintln!("Error sending log: {}", err);
                }
            }
        }
    }
}

#[derive(Serialize)]
struct LogMessage {
    message: String,
    color: String,
}

#[allow(dead_code)]
pub fn log_info(message: &str) {
    LOGGER.lock().unwrap().log_info(message);
}

#[allow(dead_code)]
pub fn log_warning(message: &str) {
    LOGGER.lock().unwrap().log_warning(message);
}

#[allow(dead_code)]
pub fn log_error(message: &str) {
    LOGGER.lock().unwrap().log_error(message);
}

#[allow(dead_code)]
pub fn log_success(message: &str) {
    LOGGER.lock().unwrap().log_success(message);
}
