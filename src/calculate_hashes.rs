use rayon::prelude::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};
use tracing::info;
use walkdir::WalkDir;

pub fn calculate_hashes(
    content_dir: &String,
    hashmap: &mut HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    info!("Calculating file hashes...");
    let mut files: Vec<walkdir::DirEntry> = Vec::new();

    for entry in WalkDir::new(content_dir) {
        let entry = entry?;
        let filetype = entry.file_type();
        if filetype.is_file() {
            files.push(entry);
        }
    }

    let hashmap_arc = Arc::new(Mutex::new(hashmap));
    files.par_iter().for_each(|entry| {
        let path = entry.path();

        let mut file = File::open(path).unwrap();
        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents).unwrap();

        let hash = blake3::hash(&file_contents).to_string();

        let filename = path.strip_prefix(content_dir).unwrap().to_string_lossy();

        info!("{}/{}", hash, filename);

        let hashmap_arc = hashmap_arc.clone();
        let mut hashmap_lock = hashmap_arc.lock().unwrap();
        (*hashmap_lock).insert(filename.to_string(), hash);
    });

    info!("Done calculating file hashes.");
    Ok(())
}
