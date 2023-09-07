use rayon::prelude::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};
use tracing::info;

pub fn calculate_hashes(
    content_dir: &String,
    hashmap: &mut HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    info!("Calculating file hashes...");
    let entries: Vec<_> = fs::read_dir(content_dir)?.collect();
    let hashmap_arc = Arc::new(Mutex::new(hashmap));

    entries.par_iter().for_each(|entry| {
        let file = entry.as_ref().unwrap();

        let filename = file.file_name().into_string().unwrap();

        let mut file = File::open(format!("{}/{}", content_dir, filename)).unwrap();
        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents).unwrap();

        let hash = blake3::hash(&file_contents).to_string();

        info!("{}/{}", hash, filename);

        let hashmap_arc = hashmap_arc.clone();
        let mut hashmap_lock = hashmap_arc.lock().unwrap();
        (*hashmap_lock).insert(filename, hash);
    });

    info!("Done calculating file hashes.");
    Ok(())
}
