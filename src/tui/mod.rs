//! Minimal interactive vault shell used as the default unlock mode.
//! The Phase 6 ratatui implementation will replace this text mode flow.

pub mod app;

use crate::security::{SecretString, shutdown_requested};
use crate::vault::ops::{
    get_secret, list_secrets, remove_secrets, set_secret, set_secret_entries, unlock_vault,
};
use anyhow::Result;
use rpassword::prompt_password;
use std::collections::HashSet;
use std::io::{self, Write};
use zeroize::Zeroize;

const HELP_TEXT: &[&str] = &[
    "Commands:",
    "  help [command]                 Show general or command-specific help",
    "  list | ls                      List secret names",
    "  get <name>                     Show secret value",
    "  set <name> [value]             Set/update secret; prompt if value omitted",
    "  set NAME=value                 Set/update a secret with env-style shorthand",
    "  import [NAME=value ...]        Import env-style assignments inline or via paste mode",
    "  rm <name ...>                  Remove one or more secrets with confirmation",
    "  info | i                       Vault metadata",
    "  refresh | reload               Reload vault from disk",
    "  export [name ...]              Export all or selected secrets",
    "  quit | exit | q                Exit",
    "",
    "Parser notes:",
    "  - Quotes are supported: set api_key \"value with spaces\"",
    "  - Backslash escapes are supported in unquoted and double-quoted text",
    "  - import accepts NAME=value and export NAME=value lines; end paste mode with '.'",
];

#[derive(Debug)]
enum ParsedCommand {
    Help(Option<String>),
    List,
    Get { name: String },
    Set { name: String, value: Option<String> },
    Import { assignments: Vec<SecretAssignment> },
    Remove { names: Vec<String> },
    Info,
    Refresh,
    Export { names: Vec<String> },
    Quit,
}

#[derive(Debug)]
struct SecretAssignment {
    name: String,
    value: String,
}

impl Zeroize for SecretAssignment {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

impl Zeroize for ParsedCommand {
    fn zeroize(&mut self) {
        match self {
            ParsedCommand::Help(topic) => topic.zeroize(),
            ParsedCommand::List => {}
            ParsedCommand::Get { name } => name.zeroize(),
            ParsedCommand::Set { name, value } => {
                name.zeroize();
                value.zeroize();
            }
            ParsedCommand::Import { assignments } => assignments.zeroize(),
            ParsedCommand::Remove { names } => names.zeroize(),
            ParsedCommand::Info => {}
            ParsedCommand::Refresh => {}
            ParsedCommand::Export { names } => names.zeroize(),
            ParsedCommand::Quit => {}
        }
    }
}

/// Launch the TUI application
pub fn launch_tui(vault_path: String) -> Result<()> {
    // Wrap passphrase in SecretString — persists for session lifetime but
    // will be zeroized when this function returns (including on signal exit).
    let passphrase = SecretString::new(prompt_password("Vault passphrase: ")?);
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    println!("dota interactive mode");
    println!("Type 'help' for available commands.");

    let stdin = io::stdin();
    let mut buffer = String::new();
    loop {
        // Check for graceful shutdown (SIGTERM/SIGINT/SIGHUP)
        if shutdown_requested() {
            break;
        }

        print!("dota> ");
        io::stdout().flush()?;

        // Zeroize the buffer properly: clear() only resets length, not memory.
        // We zeroize the underlying bytes first, then clear.
        buffer.zeroize();
        if stdin.read_line(&mut buffer).is_err() {
            break; // EOF or read error (e.g. EINTR from signal)
        }
        let line = buffer.trim();

        if line.is_empty() {
            continue;
        }

        let mut command = match parse_command_line(line) {
            Ok(command) => command,
            Err(err) => {
                println!("error: {}", err);
                continue;
            }
        };

        let keep_running = execute_command(
            &mut unlocked,
            &stdin,
            passphrase.expose(),
            &vault_path,
            &mut command,
        )?;
        command.zeroize();

        if !keep_running {
            break;
        }
    }
    // Zeroize the input buffer on exit
    buffer.zeroize();

    // All SecretStrings (passphrase, values) are zeroized here via drop.
    Ok(())
}

fn describe_key_commitment(vault: &crate::vault::format::Vault) -> &'static str {
    match (vault.version, vault.key_commitment.is_some()) {
        (6.., true) => "HMAC-SHA256 (present)",
        (6.., false) => "HMAC-SHA256 (absent)",
        (5, true) => "legacy HKDF-based v5 commitment (present)",
        (5, false) => "legacy HKDF-based v5 commitment (absent)",
        (_, true) => "present",
        (_, false) => "absent",
    }
}

fn execute_command(
    unlocked: &mut crate::vault::ops::UnlockedVault,
    stdin: &io::Stdin,
    passphrase: &str,
    vault_path: &str,
    command: &mut ParsedCommand,
) -> Result<bool> {
    match command {
        ParsedCommand::Help(topic) => print_help(topic.as_deref()),
        ParsedCommand::List => {
            let names = list_secrets(unlocked);
            if names.is_empty() {
                println!("No secrets in vault");
            } else {
                for name in names {
                    let secret = &unlocked.vault.secrets[&name];
                    println!(
                        "{} (modified: {})",
                        name,
                        secret.modified.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
        }
        ParsedCommand::Get { name } => match get_secret(unlocked, name) {
            Ok(value) => println!("{}", value.expose()),
            Err(e) => println!("error: {}", e),
        },
        ParsedCommand::Set { name, value } => {
            let value = SecretString::new(match value.take() {
                Some(value) => value,
                None => prompt_password(format!("Enter value for '{}': ", name))?,
            });

            match set_secret(unlocked, name, value.expose()) {
                Ok(_) => println!("Secret '{}' saved", name),
                Err(e) => println!("error: {}", e),
            }
        }
        ParsedCommand::Import { assignments } => {
            let assignments = if assignments.is_empty() {
                collect_import_assignments(stdin)?
            } else {
                std::mem::take(assignments)
            };

            if assignments.is_empty() {
                println!("No secrets imported");
            } else {
                handle_import_assignments(unlocked, stdin, assignments)?;
            }
        }
        ParsedCommand::Remove { names } => {
            let names = dedupe_names(std::mem::take(names));
            match confirm_remove(stdin, unlocked, &names)? {
                Some(summary) => match remove_secrets(unlocked, names) {
                    Ok(_) => println!("{}", summary),
                    Err(e) => println!("error: {}", e),
                },
                None => println!("Cancelled"),
            }
        }
        ParsedCommand::Info => print_info(unlocked, vault_path),
        ParsedCommand::Export { names } => {
            if names.is_empty() {
                for name in list_secrets(unlocked) {
                    print_exported_secret(unlocked, &name);
                }
            } else {
                for name in names {
                    print_exported_secret(unlocked, name);
                }
            }
        }
        ParsedCommand::Refresh => match unlock_vault(passphrase, vault_path) {
            Ok(fresh) => {
                *unlocked = fresh;
                println!("Refreshed vault from disk");
            }
            Err(e) => println!("error: {}", e),
        },
        ParsedCommand::Quit => return Ok(false),
    }

    Ok(true)
}

fn print_help(topic: Option<&str>) {
    match topic {
        None => {
            for line in HELP_TEXT {
                println!("{}", line);
            }
        }
        Some("help") => println!("usage: help [command]"),
        Some("list") | Some("ls") => println!("usage: list\nalias: ls"),
        Some("get") => println!("usage: get <name>"),
        Some("set") => {
            println!("usage: set <name> [value]");
            println!("       set NAME=value");
            println!("examples:");
            println!("  set api_key supersecret");
            println!("  set api_key \"value with spaces\"");
            println!("  set API_KEY=supersecret");
        }
        Some("import") | Some("paste") | Some("load") => {
            println!("usage: import [NAME=value ...]");
            println!("aliases: paste, load");
            println!("paste mode accepts:");
            println!("  NAME=value");
            println!("  export NAME=value");
            println!("terminate paste mode with: .");
        }
        Some("rm") | Some("remove") | Some("delete") | Some("del") => {
            println!("usage: rm <name ...>");
            println!("aliases: remove, delete, del");
        }
        Some("info") | Some("i") => println!("usage: info\nalias: i"),
        Some("refresh") | Some("reload") => println!("usage: refresh\nalias: reload"),
        Some("export") => {
            println!("usage: export [name ...]");
            println!("example: export DB_URL API_KEY");
        }
        Some("quit") | Some("exit") | Some("q") => println!("usage: quit\naliases: exit, q"),
        Some(other) => println!("error: unknown help topic '{}'", other),
    }
}

fn print_info(unlocked: &crate::vault::ops::UnlockedVault, vault_path: &str) {
    println!("Vault Information");
    println!("─────────────────");
    println!("Location:      {}", vault_path);
    println!("Version:       {}", unlocked.vault.version);
    println!(
        "Created:       {}",
        unlocked.vault.created.format("%Y-%m-%d %H:%M:%S")
    );
    println!("Secrets:       {}", unlocked.vault.secrets.len());
    println!("Min version:   {}", unlocked.vault.min_version);
    println!("Suite:         {}", unlocked.vault.suite);
    println!(
        "Header auth:   {}",
        describe_key_commitment(&unlocked.vault)
    );
    println!();
    println!("Cryptography");
    println!("─────────────────");
    println!("KEM:           {}", unlocked.vault.kem.algorithm);
    println!("X25519:        {}", unlocked.vault.x25519.algorithm);
    println!(
        "KDF:           {} (t={}, m={}, p={})",
        unlocked.vault.kdf.algorithm,
        unlocked.vault.kdf.time_cost,
        unlocked.vault.kdf.memory_cost,
        unlocked.vault.kdf.parallelism
    );
    println!("Encryption:    AES-256-GCM");
    println!("Hybrid KDF:    HKDF-SHA256");
    if let Some(ref info) = unlocked.vault.migrated_from {
        println!();
        println!("Migration");
        println!("─────────────────");
        println!("Original version: v{}", info.original_version);
        println!(
            "Migrated at:      {}",
            info.migrated_at.format("%Y-%m-%d %H:%M:%S")
        );
        println!(
            "Migration path:   {}",
            info.migration_path
                .iter()
                .map(|v| format!("v{}", v))
                .collect::<Vec<_>>()
                .join(" → ")
        );
    }
}

fn print_exported_secret(unlocked: &crate::vault::ops::UnlockedVault, name: &str) {
    match get_secret(unlocked, name) {
        Ok(value) => {
            let mut escaped = shell_escape(value.expose());
            println!("export {}={}", name, escaped);
            escaped.zeroize();
        }
        Err(e) => println!("error: {}", e),
    }
}

fn handle_import_assignments(
    unlocked: &mut crate::vault::ops::UnlockedVault,
    stdin: &io::Stdin,
    assignments: Vec<SecretAssignment>,
) -> Result<()> {
    validate_unique_assignment_names(&assignments)?;

    let update_count = assignments
        .iter()
        .filter(|assignment| unlocked.vault.secrets.contains_key(&assignment.name))
        .count();
    let create_count = assignments.len() - update_count;

    if assignments.len() > 1 || update_count > 0 {
        let prompt = format!(
            "Import {} secret{} ({} new, {} update{})? [y/N]: ",
            assignments.len(),
            plural_suffix(assignments.len()),
            create_count,
            update_count,
            plural_suffix(update_count),
        );
        if !prompt_yes_no(stdin, &prompt)? {
            println!("Cancelled");
            return Ok(());
        }
    }

    let entries = assignments
        .into_iter()
        .map(|assignment| (assignment.name, SecretString::new(assignment.value)))
        .collect();

    set_secret_entries(unlocked, entries)?;
    println!(
        "Imported {} secret{} ({} new, {} updated)",
        create_count + update_count,
        plural_suffix(create_count + update_count),
        create_count,
        update_count,
    );
    Ok(())
}

fn collect_import_assignments(stdin: &io::Stdin) -> Result<Vec<SecretAssignment>> {
    println!("Paste NAME=value or export NAME=value lines.");
    println!("End with a single '.' on its own line.");

    let mut assignments = Vec::new();
    let mut line_number = 0usize;
    loop {
        let mut line = read_prompt_line(stdin, "import> ")?;
        let trimmed = line.trim();

        if trimmed == "." || trimmed.eq_ignore_ascii_case("done") {
            line.zeroize();
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            line.zeroize();
            continue;
        }

        line_number += 1;
        match parse_assignment_line(trimmed) {
            Ok(assignment) => assignments.push(assignment),
            Err(err) => {
                line.zeroize();
                assignments.zeroize();
                anyhow::bail!("import line {}: {}", line_number, err);
            }
        }

        line.zeroize();
    }

    Ok(assignments)
}

fn confirm_remove(
    stdin: &io::Stdin,
    unlocked: &crate::vault::ops::UnlockedVault,
    names: &[String],
) -> Result<Option<String>> {
    if names.is_empty() {
        anyhow::bail!("usage: rm <name ...>");
    }

    let missing: Vec<&String> = names
        .iter()
        .filter(|name| !unlocked.vault.secrets.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "unknown secret{}: {}",
            plural_suffix(missing.len()),
            summarize_names(
                &missing
                    .into_iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>(),
            )
        );
    }

    let prompt = if names.len() == 1 {
        format!("Remove '{}'? [y/N]: ", names[0])
    } else {
        format!(
            "Remove {} secrets: {}? [y/N]: ",
            names.len(),
            summarize_names(&names.iter().map(String::as_str).collect::<Vec<_>>())
        )
    };

    if prompt_yes_no(stdin, &prompt)? {
        let summary = if names.len() == 1 {
            format!("Secret '{}' removed", names[0])
        } else {
            format!(
                "Removed {} secrets: {}",
                names.len(),
                summarize_names(&names.iter().map(String::as_str).collect::<Vec<_>>())
            )
        };
        Ok(Some(summary))
    } else {
        Ok(None)
    }
}

fn dedupe_names(names: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(names.len());
    for name in names {
        if seen.insert(name.clone()) {
            deduped.push(name);
        }
    }
    deduped
}

fn validate_unique_assignment_names(assignments: &[SecretAssignment]) -> Result<()> {
    let mut seen = HashSet::new();
    for assignment in assignments {
        if !seen.insert(assignment.name.as_str()) {
            anyhow::bail!("duplicate assignment for '{}'", assignment.name);
        }
    }
    Ok(())
}

fn parse_assignment_line(line: &str) -> Result<SecretAssignment> {
    let mut tokens = shell_split(line)?;
    if tokens.first().map(String::as_str) == Some("export") {
        let mut export = tokens.remove(0);
        export.zeroize();
    }

    if tokens.len() != 1 {
        tokens.zeroize();
        anyhow::bail!("expected one NAME=value assignment per line");
    }

    let token = tokens.remove(0);
    tokens.zeroize();
    parse_assignment_token(token)
}

fn parse_assignment_token(mut token: String) -> Result<SecretAssignment> {
    let (name, value) = token
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected NAME=value"))?;

    let name = name.trim();
    if name.is_empty() {
        token.zeroize();
        anyhow::bail!("secret name must not be empty");
    }
    if name.chars().any(char::is_whitespace) {
        token.zeroize();
        anyhow::bail!("secret name must not contain whitespace");
    }

    let assignment = SecretAssignment {
        name: name.to_string(),
        value: value.to_string(),
    };
    token.zeroize();
    Ok(assignment)
}

fn read_prompt_line(stdin: &io::Stdin, prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut buffer = String::new();
    stdin.read_line(&mut buffer)?;
    Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_yes_no(stdin: &io::Stdin, prompt: &str) -> Result<bool> {
    loop {
        let mut answer = read_prompt_line(stdin, prompt)?;
        let normalized = answer.trim().to_ascii_lowercase();
        answer.zeroize();
        match normalized.as_str() {
            "y" | "yes" => return Ok(true),
            "" | "n" | "no" => return Ok(false),
            _ => println!("Please answer 'y' or 'n'."),
        }
    }
}

fn summarize_names(names: &[&str]) -> String {
    const MAX_PREVIEW: usize = 4;
    if names.len() <= MAX_PREVIEW {
        names.join(", ")
    } else {
        format!(
            "{}, and {} more",
            names[..MAX_PREVIEW].join(", "),
            names.len() - MAX_PREVIEW
        )
    }
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn parse_command_line(line: &str) -> Result<ParsedCommand> {
    let mut args = shell_split(line)?;
    let Some(command) = args.first().cloned() else {
        anyhow::bail!("empty command");
    };
    let canonical = canonical_command_name(&command);
    let mut rest = args.split_off(1);
    args.zeroize();

    let parsed = match canonical {
        Some("help") => {
            ensure_max_args("help", &rest, 1)?;
            ParsedCommand::Help(rest.pop())
        }
        Some("list") => {
            ensure_no_args("list", &rest)?;
            ParsedCommand::List
        }
        Some("get") => ParsedCommand::Get {
            name: expect_exactly_one_arg("get", rest)?,
        },
        Some("set") => {
            if rest.len() == 1 && rest[0].contains('=') {
                let assignment = parse_assignment_token(rest.remove(0))?;
                ParsedCommand::Set {
                    name: assignment.name,
                    value: Some(assignment.value),
                }
            } else {
                let name = expect_required_arg("set", &mut rest, "<name>")?;
                let value = if rest.is_empty() {
                    None
                } else {
                    Some(rest.join(" "))
                };
                rest.zeroize();
                ParsedCommand::Set { name, value }
            }
        }
        Some("import") => {
            let mut assignments = Vec::with_capacity(rest.len());
            for token in rest.drain(..) {
                assignments.push(parse_assignment_token(token)?);
            }
            ParsedCommand::Import { assignments }
        }
        Some("rm") => {
            if rest.is_empty() {
                anyhow::bail!("usage: rm{}", usage_suffix("rm"));
            }
            ParsedCommand::Remove { names: rest }
        }
        Some("info") => {
            ensure_no_args("info", &rest)?;
            ParsedCommand::Info
        }
        Some("refresh") => {
            ensure_no_args("refresh", &rest)?;
            ParsedCommand::Refresh
        }
        Some("export") => ParsedCommand::Export { names: rest },
        Some("quit") => {
            ensure_no_args("quit", &rest)?;
            ParsedCommand::Quit
        }
        None => {
            let suggestion = suggest_command(&command);
            rest.zeroize();
            if let Some(suggestion) = suggestion {
                anyhow::bail!(
                    "unknown command: {} (did you mean '{}'?)",
                    command,
                    suggestion
                );
            }
            anyhow::bail!("unknown command: {}", command);
        }
        Some(_) => unreachable!("canonical command table only returns known commands"),
    };

    Ok(parsed)
}

fn shell_split(line: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if !in_single => {
                let escaped = chars
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("dangling escape at end of input"))?;
                current.push(escaped);
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if in_single || in_double {
        current.zeroize();
        args.zeroize();
        anyhow::bail!("unterminated quoted string");
    }

    if !current.is_empty() {
        args.push(current);
    } else {
        current.zeroize();
    }

    Ok(args)
}

fn canonical_command_name(command: &str) -> Option<&'static str> {
    match command {
        "help" | "?" => Some("help"),
        "list" | "ls" => Some("list"),
        "get" | "show" => Some("get"),
        "set" | "add" | "put" => Some("set"),
        "import" | "paste" | "load" => Some("import"),
        "rm" | "remove" | "delete" | "del" => Some("rm"),
        "info" | "i" => Some("info"),
        "refresh" | "reload" => Some("refresh"),
        "export" | "env" => Some("export"),
        "quit" | "exit" | "q" => Some("quit"),
        _ => None,
    }
}

fn ensure_no_args(command: &str, args: &[String]) -> Result<()> {
    if args.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("usage: {}{}", command, usage_suffix(command));
    }
}

fn ensure_max_args(command: &str, args: &[String], max: usize) -> Result<()> {
    if args.len() <= max {
        Ok(())
    } else {
        anyhow::bail!("usage: {}{}", command, usage_suffix(command));
    }
}

fn expect_exactly_one_arg(command: &str, mut args: Vec<String>) -> Result<String> {
    if args.len() == 1 {
        Ok(args.remove(0))
    } else {
        args.zeroize();
        anyhow::bail!("usage: {}{}", command, usage_suffix(command));
    }
}

fn expect_required_arg(command: &str, args: &mut Vec<String>, placeholder: &str) -> Result<String> {
    if args.is_empty() {
        anyhow::bail!("usage: {} {}", command, placeholder);
    }
    Ok(args.remove(0))
}

fn usage_suffix(command: &str) -> &'static str {
    match command {
        "help" => " [command]",
        "list" => "",
        "get" => " <name>",
        "set" => " <name> [value]",
        "import" => " [NAME=value ...]",
        "rm" => " <name ...>",
        "info" => "",
        "refresh" => "",
        "export" => " [name ...]",
        "quit" => "",
        _ => "",
    }
}

fn suggest_command(command: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for candidate in [
        "help", "list", "get", "set", "import", "rm", "info", "refresh", "export", "quit",
    ] {
        let distance = edit_distance(command, candidate);
        if distance <= 2 || candidate.starts_with(command) || command.starts_with(candidate) {
            match best {
                Some((_, best_distance)) if distance >= best_distance => {}
                _ => best = Some((candidate, distance)),
            }
        }
    }
    best.map(|(candidate, _)| candidate)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0; b_chars.len() + 1];

    for (i, a_char) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, b_char) in b_chars.iter().enumerate() {
            let cost = usize::from(a_char != *b_char);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        prev.clone_from_slice(&curr);
    }

    prev[b_chars.len()]
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::{
        ParsedCommand, edit_distance, parse_assignment_line, parse_command_line, shell_split,
        suggest_command,
    };

    #[test]
    fn test_shell_split_supports_quotes_and_escapes() {
        let args =
            shell_split(r#"set api_key "value with spaces" 'and more' escaped\ value"#).unwrap();
        assert_eq!(
            args,
            vec![
                "set",
                "api_key",
                "value with spaces",
                "and more",
                "escaped value"
            ]
        );
    }

    #[test]
    fn test_shell_split_rejects_unterminated_quotes() {
        let err = shell_split(r#"set api_key "unterminated"#).unwrap_err();
        assert!(err.to_string().contains("unterminated quoted string"));
    }

    #[test]
    fn test_parse_command_line_supports_aliases_and_export_names() {
        match parse_command_line("ls").unwrap() {
            ParsedCommand::List => {}
            other => panic!("expected list command, got {:?}", other),
        }

        match parse_command_line("export DB_URL API_KEY").unwrap() {
            ParsedCommand::Export { names } => {
                assert_eq!(names, vec!["DB_URL", "API_KEY"]);
            }
            other => panic!("expected export command, got {:?}", other),
        }

        match parse_command_line("paste DB_URL=postgres://localhost API_KEY=secret").unwrap() {
            ParsedCommand::Import { assignments } => {
                assert_eq!(assignments.len(), 2);
                assert_eq!(assignments[0].name, "DB_URL");
                assert_eq!(assignments[1].value, "secret");
            }
            other => panic!("expected import command, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_command_line_preserves_quoted_set_value() {
        match parse_command_line(r#"set api_key "value with spaces""#).unwrap() {
            ParsedCommand::Set { name, value } => {
                assert_eq!(name, "api_key");
                assert_eq!(value.as_deref(), Some("value with spaces"));
            }
            other => panic!("expected set command, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_command_line_supports_set_assignment_shorthand_and_bulk_rm() {
        match parse_command_line("set API_KEY=supersecret").unwrap() {
            ParsedCommand::Set { name, value } => {
                assert_eq!(name, "API_KEY");
                assert_eq!(value.as_deref(), Some("supersecret"));
            }
            other => panic!("expected set command, got {:?}", other),
        }

        match parse_command_line("rm first second third").unwrap() {
            ParsedCommand::Remove { names } => {
                assert_eq!(names, vec!["first", "second", "third"]);
            }
            other => panic!("expected remove command, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_assignment_line_accepts_export_roundtrip_format() {
        let assignment = parse_assignment_line(r#"export API_KEY='abc'\''123'"#).unwrap();
        assert_eq!(assignment.name, "API_KEY");
        assert_eq!(assignment.value, "abc'123");
    }

    #[test]
    fn test_parse_assignment_line_rejects_invalid_assignment() {
        let err = parse_assignment_line("export NOT AN ASSIGNMENT").unwrap_err();
        assert!(
            err.to_string()
                .contains("expected one NAME=value assignment per line")
        );
    }

    #[test]
    fn test_parse_command_line_suggests_unknown_commands() {
        let err = parse_command_line("refres").unwrap_err();
        assert!(err.to_string().contains("did you mean 'refresh'?"));
        assert_eq!(suggest_command("lst"), Some("list"));
        assert_eq!(suggest_command("imprt"), Some("import"));
    }

    #[test]
    fn test_edit_distance_basic_cases() {
        assert_eq!(edit_distance("refresh", "refresh"), 0);
        assert_eq!(edit_distance("refres", "refresh"), 1);
        assert_eq!(edit_distance("ls", "list"), 2);
    }
}
