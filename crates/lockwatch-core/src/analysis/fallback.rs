//! Regex fallback for files the parser cannot handle (syntax errors, very
//! unusual syntax). It produces the same [`JsFacts`] as the AST analysis,
//! with `parsed: false`, but it is much cruder: it cannot follow aliases or
//! evaluate split strings, and it may match text inside comments.

use super::text::{hosts_in_string, shannon_entropy, LazyRegex, LineIndex};
use super::{
    is_credential_path, is_secret_env_name, normalize_module, Hit, HostHit, JsFacts, LongString,
    NETWORK_MODULES,
};
use crate::analysis::js::LONG_STRING_CHARS;

static MODULE_USE: LazyRegex = LazyRegex::new(
    r#"(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+)["']([^"'\n]+)["']"#,
);
static COMPUTED_REQUIRE: LazyRegex = LazyRegex::new(r#"\brequire\s*\(\s*[^"'`\s)]"#);
static CHILD_PROCESS_CALL: LazyRegex =
    LazyRegex::new(r"\b(execFileSync|execFile|execSync|exec|spawnSync|spawn|fork)\s*\(");
static FETCH_CALL: LazyRegex = LazyRegex::new(r"\bfetch\s*\(");
static ENV_READ: LazyRegex =
    LazyRegex::new(r#"process\.env(?:\.([A-Za-z_$][\w$]*)|\[\s*["']([^"'\]]+)["']\s*\])"#);
static ENV_DUMP: LazyRegex = LazyRegex::new(r"JSON\.stringify\(\s*process\.env\s*\)");
static EVAL: LazyRegex = LazyRegex::new(r"\beval\s*\(");
static NEW_FUNCTION: LazyRegex = LazyRegex::new(r"\bnew\s+Function\s*\(");
static VM_RUN: LazyRegex =
    LazyRegex::new(r"\bvm\.(runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(");
static STRING_LITERAL: LazyRegex =
    LazyRegex::new(r#""(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`"#);
static READ_FILE: LazyRegex = LazyRegex::new(r"\b(readFileSync|readFile|createReadStream)\b");

pub fn analyze(source: &str) -> JsFacts {
    let lines = LineIndex::new(source);
    let hit = |offset: usize, detail: &str| Hit {
        line: lines.line_of(offset),
        evidence: lines.snippet(source, offset),
        detail: detail.to_string(),
    };
    let mut facts = JsFacts::default();

    for caps in MODULE_USE.captures_iter(source) {
        let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        let module = normalize_module(name.as_str());
        if module == "child_process" {
            facts
                .child_process_imports
                .push(hit(whole.start(), "child_process"));
        }
        if NETWORK_MODULES.contains(&module) {
            facts.network.push(hit(whole.start(), module));
        }
        if module.starts_with("./") || module.starts_with("../") {
            facts.local_requires.push(module.to_string());
        }
    }
    // Without the import, `exec(` is too common a word to mean anything.
    if !facts.child_process_imports.is_empty() {
        for caps in CHILD_PROCESS_CALL.captures_iter(source) {
            if let (Some(whole), Some(name)) = (caps.get(0), caps.get(1)) {
                let detail = format!("child_process.{}", name.as_str());
                facts.child_process_calls.push(hit(whole.start(), &detail));
            }
        }
    }
    for m in FETCH_CALL.find_iter(source) {
        facts.network.push(hit(m.start(), "fetch()"));
    }

    for caps in ENV_READ.captures_iter(source) {
        let Some(whole) = caps.get(0) else { continue };
        let name = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        if let Some(name) = name.filter(|n| is_secret_env_name(n)) {
            facts.secret_env_reads.push(hit(whole.start(), name));
        }
    }
    for m in ENV_DUMP.find_iter(source) {
        facts
            .secret_env_reads
            .push(hit(m.start(), "process.env (all variables)"));
    }

    for (re, what) in [
        (&EVAL, "eval"),
        (&NEW_FUNCTION, "new Function"),
        (&VM_RUN, "vm.runIn*"),
        (&COMPUTED_REQUIRE, "require(<computed>)"),
    ] {
        for m in re.find_iter(source) {
            facts.dynamic_code.push(hit(m.start(), what));
        }
    }

    for m in STRING_LITERAL.find_iter(source) {
        // Strip the quotes.
        let inner = &m.as_str()[1..m.as_str().len() - 1];
        if is_credential_path(inner) {
            facts.credential_paths.push(hit(m.start(), inner));
        }
        for (host, is_ip) in hosts_in_string(inner) {
            facts.hosts.push(HostHit {
                hit: hit(m.start(), &host),
                host,
                is_ip,
            });
        }
        let length = inner.chars().count();
        if length > LONG_STRING_CHARS {
            facts.long_strings.push(LongString {
                hit: hit(m.start(), "long string literal"),
                length,
                entropy: shannon_entropy(inner),
            });
        }
    }
    facts.reads_files = READ_FILE.is_match(source);

    // Keep the lists bounded, like the AST path does.
    for list in [
        &mut facts.child_process_calls,
        &mut facts.child_process_imports,
        &mut facts.network,
        &mut facts.secret_env_reads,
        &mut facts.credential_paths,
        &mut facts.dynamic_code,
    ] {
        list.truncate(50);
    }
    facts.hosts.truncate(50);
    facts.long_strings.truncate(50);
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            &MODULE_USE,
            &COMPUTED_REQUIRE,
            &CHILD_PROCESS_CALL,
            &FETCH_CALL,
            &ENV_READ,
            &ENV_DUMP,
            &EVAL,
            &NEW_FUNCTION,
            &VM_RUN,
            &STRING_LITERAL,
            &READ_FILE,
        ] {
            assert!(re.compiles());
        }
    }

    #[test]
    fn regex_facts() {
        let src = r#"
            const https = require("https") ;;; (((
            const t = process.env.GH_TOKEN, h = "http://203.0.113.7/x";
            eval(atob(x)); require(name);
        "#;
        let f = analyze(src);
        assert!(!f.parsed);
        assert_eq!(f.network.len(), 1);
        assert_eq!(f.secret_env_reads[0].detail, "GH_TOKEN");
        assert_eq!(f.secret_env_reads[0].line, 3);
        assert_eq!(f.hosts[0].host, "203.0.113.7");
        assert_eq!(f.dynamic_code.len(), 2);
    }

    #[test]
    fn exec_without_child_process_import_is_ignored() {
        let f = analyze("regex.exec(str); (((");
        assert!(f.child_process_calls.is_empty());
    }
}
