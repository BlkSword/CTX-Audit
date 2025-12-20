use std::fs;
use std::path::Path;
use anyhow::{Context, Result};
use walkdir::WalkDir;
use crate::rules::model::{Rule, RuleSet};

pub fn load_rules_from_dir<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "yaml" || extension == "yml" {
                    let content = fs::read_to_string(path)
                        .with_context(|| format!("Failed to read rule file: {:?}", path))?;
                    
                    // Try to parse as RuleSet first, then as single Rule
                    if let Ok(rule_set) = serde_yaml::from_str::<RuleSet>(&content) {
                        rules.extend(rule_set.rules);
                    } else if let Ok(rule) = serde_yaml::from_str::<Rule>(&content) {
                        rules.push(rule);
                    } else {
                        eprintln!("Failed to parse rule file: {:?}", path);
                    }
                }
            }
        }
    }

    Ok(rules)
}
