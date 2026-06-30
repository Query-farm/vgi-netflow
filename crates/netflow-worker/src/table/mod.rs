//! Table (producer) functions: `templates`.

mod templates;

use vgi::Worker;

/// Register every producer table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(templates::Templates);
}
