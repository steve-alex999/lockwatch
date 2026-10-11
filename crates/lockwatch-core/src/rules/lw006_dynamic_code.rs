//! LW006: dynamic code execution.
//!
//! `eval`, `new Function`, `vm.runIn*` and `require` of a computed string
//! run code that is not visible in the source as written. Payloads are
//! often decoded at runtime and handed to one of these. Legitimate uses
//! exist (template engines, schema compilers), so this is `medium`.

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;

pub struct DynamicCodeExecution;

impl Rule for DynamicCodeExecution {
    fn id(&self) -> &'static str {
        "LW006"
    }
    fn name(&self) -> &'static str {
        "Dynamic code execution"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn description(&self) -> &'static str {
        "eval(, new Function(, vm.runIn*, or require of a computed string"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let files = ctx
            .js
            .iter()
            .map(|(path, facts)| (path.as_str(), true, facts));
        let inline = ctx
            .install_inline
            .iter()
            .map(|i| ("package.json", false, &i.facts));
        files
            .chain(inline)
            .flat_map(|(file, has_lines, facts)| {
                facts.dynamic_code.iter().map(move |hit| {
                    self.finding(
                        ctx,
                        Some(file),
                        has_lines.then_some(hit.line),
                        &hit.evidence,
                        format!("Runs code that is built at runtime ({}).", hit.detail),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_helpers::ctx;

    #[test]
    fn eval_of_decoded_payload() {
        let c = ctx(
            "p",
            &[(
                "index.js",
                "eval(Buffer.from(payload, 'base64').toString());",
            )],
        );
        let f = DynamicCodeExecution.check(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn function_constructor_and_computed_require() {
        let c = ctx(
            "p",
            &[(
                "lib/x.js",
                "const f = new Function('a', body);\nconst m = require(name);",
            )],
        );
        let lines: Vec<_> = DynamicCodeExecution
            .check(&c)
            .iter()
            .map(|f| f.line)
            .collect();
        assert_eq!(lines, [Some(1), Some(2)]);
    }

    #[test]
    fn static_requires_and_method_named_eval_are_fine() {
        let c = ctx(
            "p",
            &[(
                "index.js",
                "const a = require('./a');\nconst b = require(`./b`);\nparser.eval('1+1');",
            )],
        );
        assert!(DynamicCodeExecution.check(&c).is_empty());
    }
}
