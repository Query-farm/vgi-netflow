//! Write the golden flow-export datagram fixtures to a directory (one datagram
//! per file) for the haybarn SQL E2E. Same byte builders the core unit tests
//! use, so the E2E and the unit tests assert the same vectors.
//!
//! Usage: `cargo run -p netflow-core --example gen_fixtures -- test/data`

use std::fs;
use std::path::Path;

use netflow_core::fixtures;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test/data".to_string());
    let dir = Path::new(&dir);
    fs::create_dir_all(dir).expect("create data dir");

    let files: &[(&str, Vec<u8>)] = &[
        ("v5.dat", fixtures::netflow_v5()),
        ("v9.dat", fixtures::netflow_v9_combined()),
        ("v9_1template.dat", fixtures::netflow_v9_template()),
        ("v9_2data.dat", fixtures::netflow_v9_data()),
        ("ipfix.dat", fixtures::ipfix_basic()),
        ("ipfix_var.dat", fixtures::ipfix_variable_enterprise()),
        ("ipfix_options.dat", fixtures::ipfix_options()),
        ("sflow.dat", fixtures::sflow_basic()),
    ];
    for (name, bytes) in files {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {name}: {e}"));
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}
