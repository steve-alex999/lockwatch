//! A package's `package.json`, read as untyped JSON.
//!
//! Real-world manifests are messy (scripts that are not strings, `os` given
//! as a string instead of a list...), so instead of a strict serde struct we
//! keep the raw `serde_json::Value` and read fields defensively.

use serde_json::Value;

/// npm lifecycle scripts that run when a package is installed. (`prepare`
/// only runs for git and local installs, but the spec includes it.)
pub const INSTALL_HOOKS: [&str; 4] = ["preinstall", "install", "postinstall", "prepare"];

/// Packages whose presence in `dependencies` means "this package builds or
/// downloads a native addon".
const NATIVE_BUILD_HELPERS: [&str; 9] = [
    "node-gyp",
    "node-gyp-build",
    "prebuild-install",
    "node-pre-gyp",
    "@mapbox/node-pre-gyp",
    "cmake-js",
    "bindings",
    "nan",
    "node-addon-api",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    raw: Value,
    /// The original text, kept to report line numbers.
    text: String,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Option<Manifest> {
        let raw: Value = serde_json::from_slice(bytes).ok()?;
        let text = String::from_utf8_lossy(bytes).into_owned();
        raw.is_object().then_some(Manifest { raw, text })
    }

    pub fn from_value(raw: Value) -> Manifest {
        let text = raw.to_string();
        Manifest { raw, text }
    }

    /// 1-based line of `"<name>":` inside the `scripts` object, for evidence.
    pub fn script_line(&self, name: &str) -> Option<u32> {
        let scripts_at = self.text.find("\"scripts\"")?;
        let needle = format!("\"{name}\"");
        let mut from = scripts_at;
        while let Some(rel) = self.text[from..].find(&needle) {
            let at = from + rel;
            let after = self.text[at + needle.len()..].trim_start();
            if after.starts_with(':') {
                let line = self.text[..at].matches('\n').count() + 1;
                return u32::try_from(line).ok();
            }
            from = at + needle.len();
        }
        None
    }

    /// The `name` field, if it is a string.
    pub fn name(&self) -> Option<&str> {
        self.raw.get("name")?.as_str()
    }

    /// The `version` field, if it is a string.
    pub fn version(&self) -> Option<&str> {
        self.raw.get("version")?.as_str()
    }

    /// The string value of `scripts.<name>`.
    pub fn script(&self, name: &str) -> Option<&str> {
        self.raw.get("scripts")?.get(name)?.as_str()
    }

    /// `(hook, command)` for each install hook that is present, in the order
    /// npm runs them.
    pub fn install_scripts(&self) -> Vec<(&'static str, String)> {
        INSTALL_HOOKS
            .iter()
            .filter_map(|hook| self.script(hook).map(|cmd| (*hook, cmd.to_string())))
            .collect()
    }

    fn has_dependency(&self, name: &str) -> bool {
        ["dependencies", "optionalDependencies"]
            .iter()
            .any(|field| {
                self.raw
                    .get(field)
                    .and_then(|deps| deps.get(name))
                    .is_some()
            })
    }

    /// Does the manifest say this package builds or ships a native binary?
    /// True for `gypfile`, a node-pre-gyp `binary` section, platform-specific
    /// packages (`os` or `cpu` set), native build helper dependencies, or an
    /// install script that runs a native build tool.
    pub fn declares_native_build(&self) -> bool {
        let truthy = |field: &str| match self.raw.get(field) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => true,
        };
        truthy("gypfile")
            || truthy("binary")
            || truthy("os")
            || truthy("cpu")
            || NATIVE_BUILD_HELPERS.iter().any(|d| self.has_dependency(d))
            || self.install_scripts().iter().any(|(_, cmd)| {
                ["node-gyp", "prebuild", "node-pre-gyp", "cmake-js"]
                    .iter()
                    .any(|tool| cmd.contains(tool))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_install_scripts_in_order() {
        let m = Manifest::from_value(json!({
            "scripts": { "postinstall": "node b.js", "test": "x", "preinstall": "node a.js",
                         "install": 42 }
        }));
        assert_eq!(
            m.install_scripts(),
            [
                ("preinstall", "node a.js".to_string()),
                ("postinstall", "node b.js".to_string())
            ]
        );
    }

    #[test]
    fn native_build_declarations() {
        assert!(Manifest::from_value(json!({"gypfile": true})).declares_native_build());
        assert!(Manifest::from_value(json!({"os": ["linux"]})).declares_native_build());
        assert!(
            Manifest::from_value(json!({"dependencies": {"node-gyp-build": "^4"}}))
                .declares_native_build()
        );
        assert!(Manifest::from_value(
            json!({"scripts": {"install": "prebuild-install || node-gyp rebuild"}})
        )
        .declares_native_build());
        assert!(
            !Manifest::from_value(json!({"name": "x", "gypfile": false})).declares_native_build()
        );
        assert!(Manifest::parse(b"[1,2]").is_none());
    }

    #[test]
    fn finds_script_lines() {
        let text = b"{\n  \"dependencies\": {\"install\": \"1\"},\n  \"scripts\": {\n    \"install\": \"node x\"\n  }\n}";
        let m = Manifest::parse(text).expect("valid");
        assert_eq!(m.script_line("install"), Some(4));
        assert_eq!(m.script_line("missing"), None);
    }
}
