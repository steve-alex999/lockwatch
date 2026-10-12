//! JavaScript analysis with the oxc parser.
//!
//! [`analyze_js`] parses a file into an abstract syntax tree (AST) and walks
//! it twice with a visitor:
//!
//! 1. **Bindings pass**: remember what local names refer to.
//!    `const cp = require('child_process')` makes `cp` mean the module;
//!    `const { exec: run } = require('child_process')` makes `run` mean
//!    `child_process.exec`; `const r = require` makes `r` an alias of require;
//!    `const m = 'child_' + 'process'` makes `m` a known string.
//! 2. **Detection pass**: record the facts the rules need, using those
//!    bindings to see through aliases and split strings.
//!
//! This is deliberately simple: one flat scope per file, no data flow
//! between functions. It catches common evasions (aliases, string
//! concatenation, `String.fromCharCode`, base64-decoded module names) but not
//! everything a determined attacker could write; see docs/RULES.md.
//!
//! If the file does not parse, [`super::fallback`] runs regexes instead.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, BinaryOperator, BindingPattern,
    CallExpression, ComputedMemberExpression, Expression, Function, ImportDeclaration,
    ImportDeclarationSpecifier, ImportExpression, NewExpression, ObjectProperty, Program,
    StaticMemberExpression, StringLiteral, TemplateLiteral, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};
use oxc_syntax::scope::ScopeFlags;

use super::text::{hosts_in_string, shannon_entropy, LineIndex};
use super::{
    fallback, is_credential_path, is_secret_env_name, normalize_module, Hit, HostHit, JsFacts,
    LongString, CHILD_PROCESS_FUNCTIONS, NETWORK_MODULES,
};

/// Strings longer than this are recorded for the obfuscation rule.
pub const LONG_STRING_CHARS: usize = 1_000;

/// At most this many hits of one kind are kept per file, so a huge bundle
/// with thousands of `require(x)` calls cannot blow up memory or the report.
const MAX_HITS_PER_KIND: usize = 50;

/// Analyse one JavaScript file. Never fails: unparseable files fall back to
/// regexes, and the returned facts say which path was taken (`parsed`).
pub fn analyze_js(path: &str, source: &str) -> JsFacts {
    let allocator = Allocator::default();
    for source_type in source_types_for(path) {
        let ret = Parser::new(&allocator, source, source_type).parse();
        if !ret.fatal_error && !ret.diagnostics.has_errors() {
            let mut facts = collect(&ret.program, source);
            facts.obfuscation = super::text::measure_obfuscation(source);
            return facts;
        }
    }
    let mut facts = fallback::analyze(source);
    facts.obfuscation = super::text::measure_obfuscation(source);
    facts
}

/// Which ways to try parsing a file, in order. `.js` can be CommonJS (which
/// allows a top-level `return`), an ES module, or contain JSX.
fn source_types_for(path: &str) -> Vec<SourceType> {
    if path.ends_with(".mjs") {
        vec![SourceType::mjs(), SourceType::mjs().with_jsx(true)]
    } else if path.ends_with(".cjs") {
        vec![SourceType::cjs()]
    } else {
        vec![
            SourceType::unambiguous(),
            SourceType::cjs(),
            SourceType::unambiguous().with_jsx(true),
        ]
    }
}

/// Run both visitor passes over a parsed program.
fn collect(program: &Program<'_>, source: &str) -> JsFacts {
    let mut collector = Collector::new(source);
    collector.visit_program(program);
    collector.detect = true;
    collector.visit_program(program);
    collector.facts.parsed = true;
    collector.facts
}

/// A value we could compute without running the code.
#[derive(Debug, Clone)]
enum StaticValue {
    Str(String),
    Array(Vec<String>),
}

/// The visitor. `'s` is the lifetime of the source text it borrows.
struct Collector<'s> {
    source: &'s str,
    lines: LineIndex,
    /// false during the bindings pass, true during the detection pass.
    detect: bool,
    require_names: HashSet<String>,
    /// local name -> module (`cp` -> `child_process`)
    module_vars: HashMap<String, String>,
    /// local name -> (module, export) (`run` -> (`child_process`, `exec`))
    member_vars: HashMap<String, (String, String)>,
    string_consts: HashMap<String, String>,
    /// aliases of `process.env`
    env_vars: HashSet<String>,
    /// aliases of `process`
    process_vars: HashSet<String>,
    /// Names declared in this file (`function fetch() {}`, `let eval`).
    /// A call to a declared `fetch` is not the global fetch.
    declared: HashSet<String>,
    facts: JsFacts,
}

impl<'s> Collector<'s> {
    fn new(source: &'s str) -> Self {
        Collector {
            source,
            lines: LineIndex::new(source),
            detect: false,
            require_names: HashSet::from(["require".to_string()]),
            module_vars: HashMap::new(),
            member_vars: HashMap::new(),
            string_consts: HashMap::new(),
            env_vars: HashSet::new(),
            process_vars: HashSet::new(),
            declared: HashSet::new(),
            facts: JsFacts::default(),
        }
    }

    fn hit(&self, span: Span, detail: impl Into<String>) -> Hit {
        let offset = span.start as usize;
        Hit {
            line: self.lines.line_of(offset),
            evidence: self.lines.snippet(self.source, offset),
            detail: detail.into(),
        }
    }

    // ---------------------------------------------------------------
    // Static evaluation: what string does this expression produce?
    // ---------------------------------------------------------------

    fn static_string(&self, expr: &Expression<'_>) -> Option<String> {
        match self.static_value(expr, 0)? {
            StaticValue::Str(s) => Some(s),
            StaticValue::Array(_) => None,
        }
    }

    /// Evaluate string-building expressions: literals, `+`, template
    /// literals, known constants, `[..].join()`, `.split('').reverse()`,
    /// `String.fromCharCode(..)`, `atob(..)` and `Buffer.from(.., 'base64')`.
    /// `depth` stops runaway recursion on deeply nested expressions.
    fn static_value(&self, expr: &Expression<'_>, depth: u8) -> Option<StaticValue> {
        if depth > 16 {
            return None;
        }
        let next = depth + 1;
        match expr.get_inner_expression() {
            Expression::StringLiteral(s) => Some(StaticValue::Str(s.value.to_string())),
            Expression::NumericLiteral(n) => Some(StaticValue::Str(js_number(n.value))),
            Expression::Identifier(id) => self
                .string_consts
                .get(id.name.as_str())
                .map(|s| StaticValue::Str(s.clone())),
            Expression::TemplateLiteral(t) => {
                let mut out = String::new();
                for (i, quasi) in t.quasis.iter().enumerate() {
                    out.push_str(quasi.value.cooked.as_ref()?.as_str());
                    if let Some(e) = t.expressions.get(i) {
                        out.push_str(&self.static_str_at(e, next)?);
                    }
                }
                Some(StaticValue::Str(out))
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                let left = self.static_str_at(&b.left, next)?;
                let right = self.static_str_at(&b.right, next)?;
                Some(StaticValue::Str(left + &right))
            }
            Expression::ArrayExpression(arr) => {
                let mut items = Vec::new();
                for el in &arr.elements {
                    // `as_expression` is None for `...spread` and holes.
                    items.push(self.static_str_at(el.as_expression()?, next)?);
                }
                Some(StaticValue::Array(items))
            }
            Expression::CallExpression(call) => self.static_call(call, next),
            _ => None,
        }
    }

    fn static_str_at(&self, expr: &Expression<'_>, depth: u8) -> Option<String> {
        match self.static_value(expr, depth)? {
            StaticValue::Str(s) => Some(s),
            StaticValue::Array(_) => None,
        }
    }

    fn static_call(&self, call: &CallExpression<'_>, depth: u8) -> Option<StaticValue> {
        let args: Vec<&Expression<'_>> = call
            .arguments
            .iter()
            .filter_map(Argument::as_expression)
            .collect();
        let callee = call.callee.get_inner_expression();

        if callee.is_specific_member_access("String", "fromCharCode") {
            let mut out = String::new();
            for arg in &args {
                let Expression::NumericLiteral(n) = arg.get_inner_expression() else {
                    return None;
                };
                out.push(char::from_u32(n.value as u32)?);
            }
            return Some(StaticValue::Str(out));
        }
        if callee.is_specific_id("atob") {
            let encoded = self.static_str_at(args.first()?, depth)?;
            return decode_base64(&encoded).map(StaticValue::Str);
        }
        if callee.is_specific_member_access("Buffer", "from") {
            let data = self.static_str_at(args.first()?, depth)?;
            let encoding = match args.get(1) {
                Some(e) => self.static_str_at(e, depth)?,
                None => "utf8".to_string(),
            };
            return match encoding.as_str() {
                "base64" => decode_base64(&data).map(StaticValue::Str),
                "hex" => decode_hex(&data).map(StaticValue::Str),
                _ => Some(StaticValue::Str(data)),
            };
        }

        // receiver.method(args) on a known string or array.
        let Expression::StaticMemberExpression(member) = callee else {
            return None;
        };
        let receiver = self.static_value(&member.object, depth)?;
        let arg_str = |i: usize| args.get(i).and_then(|e| self.static_str_at(e, depth));
        match (receiver, member.property.name.as_str()) {
            (StaticValue::Array(items), "join") => {
                let sep = if args.is_empty() {
                    ",".to_string()
                } else {
                    arg_str(0)?
                };
                Some(StaticValue::Str(items.join(&sep)))
            }
            (StaticValue::Array(mut items), "reverse") => {
                items.reverse();
                Some(StaticValue::Array(items))
            }
            (StaticValue::Str(s), "split") => {
                let sep = arg_str(0)?;
                let parts = if sep.is_empty() {
                    s.chars().map(String::from).collect()
                } else {
                    s.split(sep.as_str()).map(String::from).collect()
                };
                Some(StaticValue::Array(parts))
            }
            (StaticValue::Str(s), "concat") => {
                let mut out = s;
                for i in 0..args.len() {
                    out.push_str(&arg_str(i)?);
                }
                Some(StaticValue::Str(out))
            }
            (StaticValue::Str(s), "toString" | "valueOf" | "trim") => {
                Some(StaticValue::Str(s.trim().to_string()))
            }
            (StaticValue::Str(s), "toLowerCase") => Some(StaticValue::Str(s.to_lowercase())),
            (StaticValue::Str(s), "replace") => {
                Some(StaticValue::Str(s.replacen(&arg_str(0)?, &arg_str(1)?, 1)))
            }
            (StaticValue::Str(s), "replaceAll") => {
                Some(StaticValue::Str(s.replace(&arg_str(0)?, &arg_str(1)?)))
            }
            _ => None,
        }
    }

    // ---------------------------------------------------------------
    // What does an expression refer to?
    // ---------------------------------------------------------------

    /// Is this callee a way of calling `require`?
    fn is_require_callee(&self, callee: &Expression<'_>) -> bool {
        match callee.get_inner_expression() {
            Expression::Identifier(id) => self.require_names.contains(id.name.as_str()),
            // module.require(...), process.mainModule.require(...),
            // require.main.require(...)
            Expression::StaticMemberExpression(m) if m.property.name == "require" => {
                match m.object.get_inner_expression() {
                    Expression::Identifier(id) => id.name == "module",
                    Expression::StaticMemberExpression(inner) => {
                        inner.property.name == "mainModule" || inner.property.name == "main"
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// The module an expression evaluates to: `require('x')`, a variable
    /// bound to one, or `await import('x')`.
    fn module_of(&self, expr: &Expression<'_>) -> Option<String> {
        match expr.get_inner_expression() {
            Expression::CallExpression(call) if self.is_require_callee(&call.callee) => {
                let arg = call.arguments.first()?.as_expression()?;
                Some(normalize_module(&self.static_string(arg)?).to_string())
            }
            Expression::Identifier(id) => self.module_vars.get(id.name.as_str()).cloned(),
            Expression::AwaitExpression(a) => match a.argument.get_inner_expression() {
                Expression::ImportExpression(i) => {
                    Some(normalize_module(&self.static_string(&i.source)?).to_string())
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// `(module, export)` for `cp.exec`, `cp['ex' + 'ec']`,
    /// `require('child_process').exec`, or a destructured local name.
    fn member_of(&self, expr: &Expression<'_>) -> Option<(String, String)> {
        match expr.get_inner_expression() {
            Expression::StaticMemberExpression(m) => {
                let module = self.module_of(&m.object)?;
                Some((module, m.property.name.to_string()))
            }
            Expression::ComputedMemberExpression(m) => {
                let module = self.module_of(&m.object)?;
                Some((module, self.static_string(&m.expression)?))
            }
            Expression::Identifier(id) => self.member_vars.get(id.name.as_str()).cloned(),
            _ => None,
        }
    }

    /// Like [`Self::member_of`], but also sees through `fn.call(...)`,
    /// `fn.apply(...)` and `fn.bind(...)`.
    fn call_target(&self, callee: &Expression<'_>) -> Option<(String, String)> {
        if let Expression::StaticMemberExpression(m) = callee.get_inner_expression() {
            if matches!(m.property.name.as_str(), "call" | "apply" | "bind") {
                if let Some(target) = self.member_of(&m.object) {
                    return Some(target);
                }
            }
        }
        self.member_of(callee)
    }

    fn is_global_object(expr: &Expression<'_>) -> bool {
        matches!(
            expr.get_inner_expression(),
            Expression::Identifier(id)
                if matches!(id.name.as_str(), "global" | "globalThis" | "window" | "self")
        )
    }

    fn is_process(&self, expr: &Expression<'_>) -> bool {
        match expr.get_inner_expression() {
            Expression::Identifier(id) => {
                id.name == "process" || self.process_vars.contains(id.name.as_str())
            }
            Expression::StaticMemberExpression(m) => {
                m.property.name == "process" && Self::is_global_object(&m.object)
            }
            _ => false,
        }
    }

    /// `process.env`, `process['env']`, or an alias of it.
    fn is_env_object(&self, expr: &Expression<'_>) -> bool {
        match expr.get_inner_expression() {
            Expression::StaticMemberExpression(m) => {
                m.property.name == "env" && self.is_process(&m.object)
            }
            Expression::ComputedMemberExpression(m) => {
                self.is_process(&m.object)
                    && self.static_string(&m.expression).as_deref() == Some("env")
            }
            Expression::Identifier(id) => self.env_vars.contains(id.name.as_str()),
            _ => false,
        }
    }

    // ---------------------------------------------------------------
    // Recording bindings (both passes) and facts (detection pass)
    // ---------------------------------------------------------------

    fn bind_name(&mut self, name: &str, init: &Expression<'_>) {
        self.declared.insert(name.to_string());
        let init = init.get_inner_expression();
        let is_require_alias = match init {
            Expression::Identifier(_) | Expression::StaticMemberExpression(_) => {
                self.is_require_callee(init)
            }
            // const req = createRequire(import.meta.url)
            Expression::CallExpression(call) => {
                call.callee.is_specific_id("createRequire")
                    || call
                        .callee
                        .is_specific_member_access("module", "createRequire")
            }
            _ => false,
        };
        if is_require_alias {
            self.require_names.insert(name.to_string());
        }
        if let Some(s) = self.static_string(init) {
            self.string_consts.insert(name.to_string(), s);
        }
        if let Some(module) = self.module_of(init) {
            self.module_vars.insert(name.to_string(), module);
        } else if let Some(target) = self.member_of(init) {
            self.member_vars.insert(name.to_string(), target);
        }
        if self.is_env_object(init) {
            self.env_vars.insert(name.to_string());
        }
        if self.is_process(init) {
            self.process_vars.insert(name.to_string());
        }
    }

    fn bind_pattern(&mut self, pattern: &BindingPattern<'_>, init: &Expression<'_>) {
        match pattern {
            BindingPattern::BindingIdentifier(id) => self.bind_name(id.name.as_str(), init),
            BindingPattern::ObjectPattern(obj) => {
                let module = self.module_of(init);
                let from_env = self.is_env_object(init);
                for prop in &obj.properties {
                    let Some(key) = prop.key.static_name() else {
                        continue;
                    };
                    // `{ exec }`, `{ exec: run }` and `{ exec: run = x }`
                    let local = match &prop.value {
                        BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
                        BindingPattern::AssignmentPattern(a) => match &a.left {
                            BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let (Some(module), Some(local)) = (&module, local) {
                        self.member_vars
                            .insert(local.to_string(), (module.clone(), key.to_string()));
                    }
                    if from_env && self.detect {
                        self.record_env(&key, prop.span);
                    }
                }
            }
            _ => {}
        }
    }

    /// Append to a list unless it already holds [`MAX_HITS_PER_KIND`] items.
    fn push(list: &mut Vec<Hit>, hit: Hit) {
        if list.len() < MAX_HITS_PER_KIND {
            list.push(hit);
        }
    }

    fn record_module_use(&mut self, module: &str, span: Span) {
        let module = normalize_module(module);
        if module == "child_process" {
            let hit = self.hit(span, "child_process");
            Self::push(&mut self.facts.child_process_imports, hit);
        }
        if NETWORK_MODULES.contains(&module) {
            let hit = self.hit(span, module);
            Self::push(&mut self.facts.network, hit);
        }
        if (module.starts_with("./") || module.starts_with("../"))
            && self.facts.local_requires.len() < MAX_HITS_PER_KIND
            && !self.facts.local_requires.iter().any(|m| m == module)
        {
            self.facts.local_requires.push(module.to_string());
        }
    }

    fn record_env(&mut self, name: &str, span: Span) {
        if is_secret_env_name(name) {
            let hit = self.hit(span, name);
            Self::push(&mut self.facts.secret_env_reads, hit);
        }
    }

    /// Record a hard-coded host once per line (`{ host: '1.2.3.4' }` is
    /// both a string literal and a `host` property).
    fn record_host(&mut self, host: String, is_ip: bool, span: Span) {
        let hit = self.hit(span, host.clone());
        let duplicate = self
            .facts
            .hosts
            .iter()
            .any(|h| h.host == host && h.hit.line == hit.line);
        if !duplicate && self.facts.hosts.len() < MAX_HITS_PER_KIND {
            self.facts.hosts.push(HostHit { hit, host, is_ip });
        }
    }

    fn record_dynamic(&mut self, span: Span, what: &str) {
        let hit = self.hit(span, what);
        Self::push(&mut self.facts.dynamic_code, hit);
    }

    fn check_string(&mut self, value: &str, span: Span) {
        if is_credential_path(value) {
            let hit = self.hit(span, value);
            Self::push(&mut self.facts.credential_paths, hit);
        }
        for (host, is_ip) in hosts_in_string(value) {
            self.record_host(host, is_ip, span);
        }
        let length = value.chars().count();
        if length > LONG_STRING_CHARS && self.facts.long_strings.len() < MAX_HITS_PER_KIND {
            let hit = self.hit(span, "long string literal");
            self.facts.long_strings.push(LongString {
                hit,
                length,
                entropy: shannon_entropy(value),
            });
        }
    }

    fn check_call(&mut self, call: &CallExpression<'_>) {
        let callee = call.callee.get_inner_expression();

        if self.is_require_callee(callee) {
            if let Some(arg) = call.arguments.first().and_then(Argument::as_expression) {
                match self.static_string(arg) {
                    Some(module) => self.record_module_use(&module, call.span),
                    None => self.record_dynamic(call.span, "require(<computed>)"),
                }
            }
            return;
        }

        // A local variable bound to a network client: `const f = require('node-fetch'); f(url)`.
        if let Expression::Identifier(id) = callee {
            if let Some(module) = self.module_vars.get(id.name.as_str()) {
                if NETWORK_MODULES.contains(&module.as_str()) {
                    let hit = self.hit(call.span, module.clone());
                    Self::push(&mut self.facts.network, hit);
                }
            }
        }

        // Global functions: eval(...), Function(...), fetch(...), also via
        // globalThis.eval or the indirect form (0, eval)(...). A name declared
        // in this file is a local function, not the global one.
        let global_name = match callee {
            Expression::Identifier(id) if !self.declared.contains(id.name.as_str()) => {
                Some(id.name.as_str())
            }
            Expression::StaticMemberExpression(m) if Self::is_global_object(&m.object) => {
                Some(m.property.name.as_str())
            }
            Expression::SequenceExpression(seq) => match seq.expressions.last() {
                Some(Expression::Identifier(id)) if id.name == "eval" => Some("eval"),
                _ => None,
            },
            _ => None,
        };
        match global_name {
            Some("eval") => self.record_dynamic(call.span, "eval"),
            Some("Function") => self.record_dynamic(call.span, "Function()"),
            Some("fetch") => {
                let hit = self.hit(call.span, "fetch()");
                Self::push(&mut self.facts.network, hit);
            }
            _ => {}
        }

        // JSON.stringify(process.env) dumps every variable, secrets included.
        if callee.is_specific_member_access("JSON", "stringify") {
            if let Some(arg) = call.arguments.first().and_then(Argument::as_expression) {
                if self.is_env_object(arg) {
                    let hit = self.hit(call.span, "process.env (all variables)");
                    Self::push(&mut self.facts.secret_env_reads, hit);
                }
            }
        }

        if let Some((module, member)) = self.call_target(callee) {
            match module.as_str() {
                "child_process" if CHILD_PROCESS_FUNCTIONS.contains(&member.as_str()) => {
                    let hit = self.hit(call.span, format!("child_process.{member}"));
                    Self::push(&mut self.facts.child_process_calls, hit);
                }
                "vm" if member.starts_with("runIn") || member == "compileFunction" => {
                    self.record_dynamic(call.span, &format!("vm.{member}"));
                }
                _ => {}
            }
        }

        // File reads: fs may be wrapped (fs-extra, graceful-fs, promisify),
        // so match the function name wherever it is called.
        let fn_name = match callee {
            Expression::Identifier(id) => Some(id.name.as_str()),
            Expression::StaticMemberExpression(m) => Some(m.property.name.as_str()),
            _ => None,
        };
        if matches!(
            fn_name,
            Some("readFile" | "readFileSync" | "createReadStream")
        ) {
            self.facts.reads_files = true;
        }
    }

    fn check_new(&mut self, expr: &NewExpression<'_>) {
        let callee = expr.callee.get_inner_expression();
        let is_function = callee.is_specific_id("Function")
            || matches!(callee, Expression::StaticMemberExpression(m)
                if m.property.name == "Function" && Self::is_global_object(&m.object));
        if is_function {
            self.record_dynamic(expr.span, "new Function");
        } else if self
            .member_of(callee)
            .is_some_and(|(module, member)| module == "vm" && member == "Script")
        {
            self.record_dynamic(expr.span, "new vm.Script");
        }
    }
}

/// The `Visit` trait (from oxc_ast_visit) has one method per node type. Each
/// default implementation just walks into the children; we override the ones
/// we care about and call `walk::...` to keep walking.
impl<'a> Visit<'a> for Collector<'_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        if let Some(id) = &func.id {
            self.declared.insert(id.name.to_string());
        }
        walk::walk_function(self, func, flags);
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        match &decl.init {
            Some(init) => self.bind_pattern(&decl.id, init),
            None => {
                if let BindingPattern::BindingIdentifier(id) = &decl.id {
                    self.declared.insert(id.name.to_string());
                }
            }
        }
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &expr.left {
            self.bind_name(id.name.as_str(), &expr.right);
        }
        walk::walk_assignment_expression(self, expr);
    }

    fn visit_import_declaration(&mut self, decl: &ImportDeclaration<'a>) {
        let module = normalize_module(decl.source.value.as_str()).to_string();
        if self.detect {
            self.record_module_use(&module, decl.span);
        } else if let Some(specifiers) = &decl.specifiers {
            for spec in specifiers {
                match spec {
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        self.member_vars.insert(
                            s.local.name.to_string(),
                            (module.clone(), s.imported.name().to_string()),
                        );
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        self.module_vars
                            .insert(s.local.name.to_string(), module.clone());
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        self.module_vars
                            .insert(s.local.name.to_string(), module.clone());
                    }
                }
            }
        }
        walk::walk_import_declaration(self, decl);
    }

    fn visit_import_expression(&mut self, expr: &ImportExpression<'a>) {
        if self.detect {
            if let Some(module) = self.static_string(&expr.source) {
                self.record_module_use(&module, expr.span);
            }
        }
        walk::walk_import_expression(self, expr);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.detect {
            self.check_call(call);
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, expr: &NewExpression<'a>) {
        if self.detect {
            self.check_new(expr);
        }
        walk::walk_new_expression(self, expr);
    }

    fn visit_static_member_expression(&mut self, expr: &StaticMemberExpression<'a>) {
        if self.detect && self.is_env_object(&expr.object) {
            self.record_env(expr.property.name.as_str(), expr.span);
        }
        walk::walk_static_member_expression(self, expr);
    }

    fn visit_computed_member_expression(&mut self, expr: &ComputedMemberExpression<'a>) {
        if self.detect && self.is_env_object(&expr.object) {
            if let Some(key) = self.static_string(&expr.expression) {
                self.record_env(&key, expr.span);
            }
        }
        walk::walk_computed_member_expression(self, expr);
    }

    fn visit_object_property(&mut self, prop: &ObjectProperty<'a>) {
        // { host: 'c2.example.invalid' } passed to http.request(...)
        if self.detect {
            let key = prop.key.static_name();
            if matches!(key.as_deref(), Some("host" | "hostname")) {
                if let Some(value) = self.static_string(&prop.value) {
                    let is_domain = value.contains('.')
                        && !value.contains(['/', ' '])
                        && value != "localhost"
                        && !value.starts_with("127.");
                    if is_domain {
                        let is_ip = super::text::is_ipv4(&value);
                        self.record_host(value, is_ip, prop.span);
                    }
                }
            }
        }
        walk::walk_object_property(self, prop);
    }

    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        if self.detect {
            self.check_string(lit.value.as_str(), lit.span);
        }
    }

    fn visit_template_literal(&mut self, lit: &TemplateLiteral<'a>) {
        if self.detect {
            let text: String = lit
                .quasis
                .iter()
                .filter_map(|q| q.value.cooked.as_ref().map(|c| c.as_str()))
                .collect();
            self.check_string(&text, lit.span);
        }
        walk::walk_template_literal(self, lit);
    }
}

/// Format a number the way JavaScript's `String(n)` does for simple cases.
fn js_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn decode_base64(s: &str) -> Option<String> {
    let bytes = BASE64.decode(s.trim()).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn decode_hex(s: &str) -> Option<String> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect();
    Some(String::from_utf8_lossy(&bytes?).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details(hits: &[Hit]) -> Vec<&str> {
        hits.iter().map(|h| h.detail.as_str()).collect()
    }

    #[test]
    fn finds_child_process_through_aliases() {
        let src = r#"
            const cp = require('child_process');
            cp.exec('id');
            const { execSync: run } = require("node:child_process");
            run('whoami');
            require('child_process').spawn('sh');
            const r = require; const m = 'child_' + 'process';
            r(m).fork('x.js');
            cp['ex' + 'ecSync']('ls');
            cp.execFile.call(null, 'ls');
        "#;
        let f = analyze_js("install.js", src);
        assert!(f.parsed);
        assert_eq!(
            details(&f.child_process_calls),
            [
                "child_process.exec",
                "child_process.execSync",
                "child_process.spawn",
                "child_process.fork",
                "child_process.execSync",
                "child_process.execFile"
            ]
        );
        assert_eq!(f.child_process_calls[0].line, 3);
        assert_eq!(f.child_process_imports.len(), 4);
    }

    #[test]
    fn decodes_obfuscated_module_names() {
        let src = r#"
            const a = require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());
            a.exec('x');
            const b = require(String.fromCharCode(104,116,116,112,115));
            const c = require(['ss', 'ecor', 'p_dlihc'].join('').split('').reverse().join(''));
            c.spawn('y');
            const d = require(atob('bmV0'));
        "#;
        let f = analyze_js("x.js", src);
        assert_eq!(
            details(&f.child_process_calls),
            ["child_process.exec", "child_process.spawn"]
        );
        assert_eq!(details(&f.network), ["https", "net"]);
    }

    #[test]
    fn esm_imports_and_fetch() {
        let src = r#"
            import { exec } from 'child_process';
            import * as https from 'node:https';
            exec('id');
            await fetch('http://203.0.113.5/p');
            const dns = await import('dns');
        "#;
        let f = analyze_js("x.mjs", src);
        assert!(f.parsed);
        assert_eq!(details(&f.child_process_calls), ["child_process.exec"]);
        assert_eq!(details(&f.network), ["https", "fetch()", "dns"]);
        assert_eq!(f.hosts[0].host, "203.0.113.5");
        assert!(f.hosts[0].is_ip);
    }

    #[test]
    fn env_secrets_and_credential_files() {
        let src = r#"
            const t = process.env.NPM_TOKEN;
            const k = process.env['AWS_SECRET_ACCESS_KEY'];
            const { GITHUB_TOKEN, HOME } = process.env;
            const env = process.env; env.MY_API_KEY;
            const all = JSON.stringify(process.env);
            const ok = process.env.NODE_ENV;
            const p = require('path').join(require('os').homedir(), '.npmrc');
            require('fs').readFileSync(p);
        "#;
        let f = analyze_js("x.js", src);
        assert_eq!(
            details(&f.secret_env_reads),
            [
                "NPM_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
                "GITHUB_TOKEN",
                "MY_API_KEY",
                "process.env (all variables)"
            ]
        );
        assert_eq!(details(&f.credential_paths), [".npmrc"]);
        assert!(f.reads_files);
    }

    #[test]
    fn dynamic_code() {
        let src = r#"
            eval('1');
            (0, eval)('2');
            new Function('return 1');
            const vm = require('vm'); vm.runInNewContext('3');
            require(process.argv[2]);
            require('./ok');
            globalThis.eval('4');
        "#;
        let f = analyze_js("x.js", src);
        assert_eq!(
            details(&f.dynamic_code),
            [
                "eval",
                "eval",
                "new Function",
                "vm.runInNewContext",
                "require(<computed>)",
                "eval"
            ]
        );
        assert_eq!(f.local_requires, ["./ok"]);
    }

    #[test]
    fn benign_code_has_no_findings() {
        let src = r#"
            'use strict';
            const path = require('path');
            module.exports = function add(a, b) { return a + b; };
            const mode = process.env.NODE_ENV;
            const url = 'https://github.com/example/repo';
        "#;
        let f = analyze_js("index.js", src);
        assert!(f.parsed);
        assert!(f.child_process_calls.is_empty());
        assert!(f.network.is_empty());
        assert!(f.secret_env_reads.is_empty());
        assert!(f.dynamic_code.is_empty());
        // Hard-coded hosts are recorded, but only matter in install-time files.
        assert_eq!(f.hosts.len(), 1);
    }

    #[test]
    fn local_functions_shadow_globals() {
        let src = r#"
            function fetch(url) { return cache[url]; }
            fetch('x');
            const nf = require('node-fetch');
            nf('https://example.invalid');
        "#;
        let f = analyze_js("x.js", src);
        assert_eq!(details(&f.network), ["node-fetch", "node-fetch"]);
    }

    #[test]
    fn commonjs_top_level_return_and_jsx_parse() {
        assert!(analyze_js("a.js", "if (x) return;\nmodule.exports = 1;").parsed);
        assert!(analyze_js("b.js", "const el = <div>{x}</div>;").parsed);
    }

    #[test]
    fn unparseable_files_use_the_regex_fallback() {
        let src = "const cp = require('child_process'); cp.exec('id'; ((( ";
        let f = analyze_js("broken.js", src);
        assert!(!f.parsed);
        assert_eq!(f.child_process_imports.len(), 1);
        assert_eq!(details(&f.child_process_calls), ["child_process.exec"]);
    }
}
