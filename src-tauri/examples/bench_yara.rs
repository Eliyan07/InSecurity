use antivirus_ui_lib::core::yara_scanner::YaraScanner;
use std::{env, fs, path::PathBuf, time::Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("resources/bench_samples");
    let dir_path = PathBuf::from(dir);

    if !dir_path.exists() || !dir_path.is_dir() {
        eprintln!("Bench directory not found: {}", dir);
        std::process::exit(1);
    }

    let scanner = YaraScanner::new();

    let mut total_files = 0usize;
    let start_total = Instant::now();

    for entry in fs::read_dir(&dir_path).expect("read_dir failed") {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        total_files += 1;
        let content = match fs::read(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read {:?}: {}", path, e);
                continue;
            }
        };

        let t = Instant::now();
        let matches = scanner.scan(&content);
        let elapsed = t.elapsed();

        println!(
            "{:?}: {} matches - {:.2?}",
            path.file_name().unwrap_or_default(),
            matches.len(),
            elapsed
        );
    }

    let total_elapsed = start_total.elapsed();
    println!("Processed {} files in {:.2?}", total_files, total_elapsed);
}
