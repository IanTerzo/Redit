use colored::*;
use reqwest::blocking::Client;
use serde::Serialize;

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

            match self
                .client
                .post(endpoint)
                .json(&log_message)
                .send()
            {
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