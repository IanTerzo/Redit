use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UploaderInfo {
    pub public: bool,
    pub name: String,
    pub files_size: i32
}

