mod upload;
use upload::{host};
mod types;
use types::{UploaderInfo};

fn main() {

    let uploader_info = UploaderInfo {
        public: true,
        name: "Ian".to_string(),
        files_size: 4
    };

    host(uploader_info)
}
