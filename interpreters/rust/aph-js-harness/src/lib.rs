// Every public item here is read by someone deciding whether to trust the
// second-engine result, so undocumented surface is a defect.
#![warn(missing_docs)]

//! The TypeScript implementation's crypto-free core, run under a SECOND
//! ECMAScript engine, from cargo.
//!
//! # Why a second engine is a test and not a duplicate runner
//!
//! RFC 8785 §3.2.2.3 does not define number serialization. It DEFERS to
//! ECMAScript `Number::toString`, which means the canonical bytes an APH
//! signature covers are decided, in the TypeScript implementation, by the
//! host's float formatter. Running that canonicalizer under one runtime proves
//! that this canonicalizer agrees with that runtime — it cannot distinguish a
//! correct implementation from one that has quietly inherited a host-specific
//! assumption. Running the SAME COMPILED JavaScript under an independently
//! written engine catches exactly that class, and it is the cheapest real
//! evidence available that the second implementation is portable to the
//! browsers, edge runtimes and alternative runtimes a stranger will actually
//! use.
//!
//! # One table, two engines
//!
//! No expectation lives in this crate. `interpreters/typescript/testkit/
//! jcs_vectors.json` is the table; the node suite reads it, and so does this
//! harness, passing the file's own text through unmodified. The table is the
//! contract and the two engines are adapters to it. A row that passes under one
//! and fails under the other is reported as a DIVERGENCE with both outputs
//! printed — it is a conformance finding about the TypeScript, an accidental
//! host-ism, and is never papered over with a per-engine branch. If the second
//! engine is itself provably nonconformant on a case, that case is skipped with
//! a citation to the engine's own issue, never silently.
//!
//! # What this deliberately does NOT cover
//!
//! Cryptography. A JavaScript LANGUAGE engine has no WebCrypto, and the
//! TypeScript implementation's every hash and signature goes through
//! SubtleCrypto by design. So the scope here is the crypto-free core — which is
//! most of the protocol logic: canonicalization, strict parse, the §7.1.11
//! proof-structure and mode rules, and the §11 refusal codes reachable without
//! a signature. `verify.js`, `mint.js`, `signers.js` and `webcrypto.js` are not
//! loaded and their paths stay gated under the runtime that has WebCrypto.
//!
//! A Rust-backed SubtleCrypto shim — real Ed25519 and P-256 behind a
//! `crypto.subtle` object inside the engine — would let cargo alone exercise
//! the full TypeScript verifier. It is named here as FUTURE WORK and is
//! deliberately not smuggled in: it would mean this harness held opinions about
//! signatures, and the current scope is honest about which half is unchecked.
//!
//! # The one host API that is supplied
//!
//! `TextEncoder`. It is a WHATWG host API rather than an ECMAScript one, so a
//! language engine does not have it, and the strict parser needs it for
//! §7.1.6's preview bound, which is stated in BYTES. The shim is the minimum
//! surface — `encode` returning UTF-8 — and the conversion is Rust's own, not a
//! hand-written encoder. Nothing is asserted about its output: the byte-level
//! assertion stays in the node suite, because a row checked against a supplied
//! encoder would be measuring this harness rather than the implementation.
//!
//! # Running it
//!
//! This crate is OUTSIDE the workspace's default members, so plain
//! `cargo test` never reaches it — it needs the compiled JavaScript on disk,
//! and requiring a Node toolchain to test the protocol crates would be a
//! coupling worth refusing. Build first, then name the package:
//!
//! ```text
//! cd interpreters/typescript && npm install && npm run build
//! cd ../rust && cargo test -p aph-js-harness
//! ```
//!
//! No Node process is ever spawned. The harness reads build output the way
//! every other cross-check in this repository reads committed bytes.

/// The driver module's source, compiled in rather than read from disk.
///
/// Embedding it keeps the harness a single artifact: the only files that must
/// exist at run time are the ones the TypeScript build produced, so a missing
/// driver can never be confused with a missing build.
const DRIVER_SOURCE: &str = include_str!("../js/driver.mjs");

/// The virtual path the driver module is registered under.
///
/// It is a name inside the TypeScript directory and NOT a file on disk. The
/// module resolver needs a referrer path to resolve `./dist/...` against, and
/// giving the driver a path inside the module root is how it gets one without
/// this crate writing anything into a directory it does not own.
const DRIVER_MODULE_NAME: &str = "aph_boa_driver.mjs";

/// Installs the host APIs a language engine does not have. See the crate docs.
const TEXT_ENCODER_SHIM: &str = r#"
(function installHostApis(scope) {
  function TextEncoder() {}
  TextEncoder.prototype.encoding = 'utf-8';
  TextEncoder.prototype.encode = function encode(input) {
    return scope.__aphHostUtf8Encode(input === undefined ? '' : input);
  };
  scope.TextEncoder = TextEncoder;
})(globalThis);
"#;

/// One row of the shared table's `canonicalize` section.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct CanonicalizeCase {
  /// The row's name, which is also how a result is matched back to it.
  pub name: std::string::String,
  /// WHY the row exists. Printed on failure, so a divergence arrives with its
  /// own explanation instead of sending a reader to the specification.
  pub pins: std::string::String,
  /// The input's JSON TEXT. Parsed by whichever engine is running.
  pub json: std::string::String,
  /// The expected canonical output, byte for byte.
  pub canonical: std::string::String,
}

/// One row of the shared table's `refuse` section.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct RefuseCase {
  /// The row's name.
  pub name: std::string::String,
  /// WHY the row exists.
  pub pins: std::string::String,
  /// A closed tag naming a non-finite double, because JSON has no literal for
  /// one and an evaluated expression in a data file read by two engines is a
  /// larger hole than three constants are worth.
  #[serde(rename = "nonFinite")]
  pub non_finite: std::string::String,
  /// The constructor name the refusal is expected to carry.
  #[serde(rename = "errorName")]
  pub error_name: std::string::String,
}

/// The shared expectation table, as both engines read it.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct JcsVectorTable {
  /// Rows that must canonicalize to a stated text.
  pub canonicalize: std::vec::Vec<CanonicalizeCase>,
  /// Rows that must be refused rather than serialized.
  pub refuse: std::vec::Vec<RefuseCase>,
}

/// A value the implementation threw, reduced to the facts worth asserting on.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct ThrownValue {
  /// The constructor name, e.g. `TypeError`, `AphError`, `AphParseError`.
  pub name: std::string::String,
  /// The message, for the failure report rather than for an assertion.
  pub message: std::string::String,
  /// The §11 code, present when an `AphError` was thrown.
  #[serde(default)]
  pub code: std::option::Option<std::string::String>,
  /// The JSON path of the offending member, present on a strict-parse failure.
  #[serde(default)]
  pub path: std::option::Option<std::string::String>,
}

/// What the second engine produced for one table row.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct CaseResult {
  /// The row's name, echoed so results cannot be matched by position.
  pub name: std::string::String,
  /// The canonical text, when the row canonicalized.
  #[serde(default)]
  pub canonical: std::option::Option<std::string::String>,
  /// What was thrown, when the row was refused.
  #[serde(default)]
  pub threw: std::option::Option<ThrownValue>,
  /// Set when a `refuse` row named a tag the driver does not know.
  #[serde(default, rename = "unknownTag")]
  pub unknown_tag: std::option::Option<std::string::String>,
}

/// What the crypto-free half of §8.3 decided about one envelope.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct EnvelopeInspection {
  /// Whether §8.3 step 1 (strict parse) succeeded.
  pub parsed: bool,
  /// The strict-parse failure, when it did not.
  #[serde(default, rename = "parseError")]
  pub parse_error: std::option::Option<ThrownValue>,
  /// The `attestationMode` LABEL, defaulted per §7.1.7.
  #[serde(default, rename = "declaredMode")]
  pub declared_mode: std::option::Option<std::string::String>,
  /// The mode the STRUCTURE proves, when the §7.1.11 checks passed.
  #[serde(default, rename = "structureMode")]
  pub structure_mode: std::option::Option<std::string::String>,
  /// The structure refusal, when they did not.
  #[serde(default, rename = "structureError")]
  pub structure_error: std::option::Option<ThrownValue>,
  /// Whether canonicalizing the canonical form reproduced it exactly.
  #[serde(default, rename = "canonicalStable")]
  pub canonical_stable: std::option::Option<bool>,
}

/// The §11 taxonomy as the implementation's own module declares it.
#[derive(serde::Deserialize, std::fmt::Debug)]
pub struct ErrorTaxonomy {
  /// The ordered code list.
  pub codes: std::vec::Vec<std::string::String>,
  /// Code to variant name. A map, so the two declarations can be checked
  /// against each other in both directions.
  pub variants: std::collections::BTreeMap<std::string::String, std::string::String>,
}

/// The absolute path of the second implementation's directory.
///
/// Resolved from this crate's own manifest directory, so it follows the crate
/// if the tree moves, and canonicalized because the module resolver compares
/// the driver's path against its root by prefix.
#[must_use]
pub fn typescript_root() -> std::path::PathBuf {
  let relative = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../typescript");
  relative.canonicalize().unwrap_or_else(|error| {
    std::panic!(
      "could not resolve the TypeScript implementation directory at {}: {}",
      relative.display(),
      error
    )
  })
}

/// The compiled module every driver import is rooted at.
#[must_use]
pub fn dist_entry() -> std::path::PathBuf {
  typescript_root().join("dist").join("src").join("jcs.js")
}

/// The shared expectation table, read from the file the node suite reads.
///
/// Returns the parsed table AND its original text: the text is what crosses
/// into the engine, unmodified, so neither side re-encodes the other's data.
///
/// # Panics
///
/// If the table is missing or malformed. There is no useful degraded mode — a
/// harness that silently ran zero rows would be worse than one that stops.
#[must_use]
pub fn shared_jcs_table() -> (JcsVectorTable, std::string::String) {
  let path = typescript_root().join("testkit").join("jcs_vectors.json");
  let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
    std::panic!(
      "could not read the shared JCS expectation table at {}: {}",
      path.display(),
      error
    )
  });
  let table: JcsVectorTable = serde_json::from_str(&text).unwrap_or_else(|error| {
    std::panic!(
      "the shared JCS expectation table at {} is not the expected shape: {}",
      path.display(),
      error
    )
  });
  (table, text)
}

/// The message a run gets when the TypeScript has not been built.
///
/// Spelled out rather than left to a module-resolution error, which would blame
/// a missing file inside `dist/` and read as a broken harness.
fn build_first_message(entry: &std::path::Path) -> std::string::String {
  std::format!(
    "\nBUILD FIRST — there is no compiled JavaScript for the second engine to run.\n\n\
     This harness runs the TypeScript implementation's BUILD OUTPUT, which is why it sits\n\
     outside the workspace's default members: testing the protocol crates must never require\n\
     a Node toolchain to have run. Build the second implementation, then name this package:\n\n\
     \x20   cd interpreters/typescript\n\
     \x20   npm install\n\
     \x20   npm run build\n\
     \x20   cd ../rust && cargo test -p aph-js-harness\n\n\
     Looked for: {}\n",
    entry.display()
  )
}

/// A booted engine holding the driver module, ready to be called.
///
/// One per test. The engine is single-threaded by construction, and a shared
/// one would need a lock — which this repository does not add for test
/// plumbing.
///
/// Booting is cheap, and what it parses is the whole REACHABLE graph, not the
/// driver's import list. Enumerated from the compiled output rather than
/// counted from the `import` lines: `aph_boa_driver.mjs`; its four direct
/// imports `dist/src/jcs.js`, `dist/src/errors.js`, `dist/src/parse.js` and
/// `dist/src/structure.js`; and the three those pull in transitively —
/// `dist/src/types.js` (from both `parse.js` and `structure.js`),
/// `dist/src/didkey.js` (from `structure.js`) and `dist/src/baseenc.js` (from
/// `didkey.js`). Eight modules.
///
/// The list is spelled out because this is the only place the documentation
/// says how much JavaScript enters the engine, and the two transitive tails are
/// exactly the ones a reader auditing the crypto-free scope would never see by
/// reading the driver: `didkey.js` and `baseenc.js` are evaluated. They belong
/// in scope — did:key derivation is multicodec prefix arithmetic and base58btc
/// is a transport encoding, so nothing on this list hashes, signs or verifies —
/// but that is a conclusion to be checked against the modules, which requires
/// knowing they are there.
pub struct Engine {
  context: boa_engine::Context,
  driver: boa_engine::Module,
}

impl Engine {
  /// Boots the engine, installs the host APIs, and evaluates the driver module.
  ///
  /// # Panics
  ///
  /// With a BUILD FIRST message when the TypeScript build output is absent, and
  /// with the engine's own error otherwise.
  #[must_use]
  pub fn boot() -> Self {
    let root = typescript_root();
    let entry = dist_entry();
    std::assert!(entry.is_file(), "{}", build_first_message(&entry));

    let loader = std::rc::Rc::new(
      boa_engine::module::SimpleModuleLoader::new(&root).unwrap_or_else(|error| {
        std::panic!("could not root the module loader at {}: {}", root.display(), error)
      }),
    );
    let mut context = boa_engine::Context::builder()
      .module_loader(std::rc::Rc::clone(&loader))
      .build()
      .unwrap_or_else(|error| std::panic!("could not build the engine: {error}"));

    install_host_apis(&mut context);

    let driver_path = root.join(DRIVER_MODULE_NAME);
    let source = boa_engine::Source::from_bytes(DRIVER_SOURCE).with_path(driver_path.as_path());
    let driver = boa_engine::Module::parse(source, std::option::Option::None, &mut context)
      .unwrap_or_else(|error| std::panic!("the harness driver module does not parse: {error}"));
    loader.insert(driver_path, driver.clone());

    let promise = driver.load_link_evaluate(&mut context);
    context
      .run_jobs()
      .unwrap_or_else(|error| std::panic!("the engine's job queue failed: {error}"));
    match promise.state() {
      boa_engine::builtins::promise::PromiseState::Fulfilled(_) => {}
      boa_engine::builtins::promise::PromiseState::Pending => std::panic!(
        "the driver module never settled — every module in scope is synchronous, so this \
         means a module load is still outstanding"
      ),
      boa_engine::builtins::promise::PromiseState::Rejected(reason) => {
        let detail = match reason.to_string(&mut context) {
          std::result::Result::Ok(text) => text.to_std_string_escaped(),
          std::result::Result::Err(_) => std::string::String::from("<unprintable rejection>"),
        };
        std::panic!(
          "loading the compiled TypeScript core under the second engine failed: {detail}\n\n\
           If this names a syntax or feature error, it is a REPORTABLE finding: the compiled \
           output uses something the pinned engine does not implement.\n\
           Module root: {}",
          root.display()
        );
      }
    }

    Self { context, driver }
  }

  /// Calls one driver export with a JSON request and returns its JSON answer.
  ///
  /// Text in both directions, which is the same boundary rule every binding in
  /// this repository follows and for the same reason: the envelope's `proof`
  /// member is an untagged union whose arm is decided by position, so a value
  /// that crosses as a host object lets a second deserializer decide which arm
  /// it is.
  ///
  /// # Panics
  ///
  /// If the export is missing, is not callable, throws, or answers with
  /// anything other than a string. All four are harness defects rather than
  /// findings about the implementation, and none has a useful degraded mode.
  pub fn call(&mut self, export: &str, request_json: &str) -> std::string::String {
    let name = boa_engine::JsString::from(export);
    let value = self
      .driver
      .get_value(name, &mut self.context)
      .unwrap_or_else(|error| std::panic!("the driver exports no `{export}`: {error}"));
    let callable = value
      .as_function()
      .unwrap_or_else(|| std::panic!("the driver's `{export}` is not a function"));

    let argument = boa_engine::JsValue::from(boa_engine::JsString::from(request_json));
    let answer = callable
      .call(
        &boa_engine::JsValue::undefined(),
        &[argument],
        &mut self.context,
      )
      .unwrap_or_else(|error| std::panic!("the driver's `{export}` threw: {error}"));
    self
      .context
      .run_jobs()
      .unwrap_or_else(|error| std::panic!("the engine's job queue failed after `{export}`: {error}"));

    answer
      .as_string()
      .unwrap_or_else(|| std::panic!("the driver's `{export}` did not answer with a string"))
      // Escaped rather than lossy: an unpaired surrogate in the answer stays
      // VISIBLE in the failure report instead of collapsing into U+FFFD, which
      // would turn a real divergence into an unreadable one.
      .to_std_string_escaped()
  }

  /// Deserializes a driver answer, naming the export when the shape is wrong.
  ///
  /// # Panics
  ///
  /// If the answer does not deserialize into `T`.
  pub fn call_json<T: serde::de::DeserializeOwned>(
    &mut self,
    export: &str,
    request_json: &str,
  ) -> T {
    let answer = self.call(export, request_json);
    serde_json::from_str(&answer)
      .unwrap_or_else(|error| std::panic!("the driver's `{export}` answered unexpectedly: {error}"))
  }
}

/// Registers the WHATWG surface the strict parser needs. See the crate docs.
fn install_host_apis(context: &mut boa_engine::Context) {
  context
    .register_global_callable(
      boa_engine::JsString::from("__aphHostUtf8Encode"),
      1,
      boa_engine::NativeFunction::from_fn_ptr(host_utf8_encode),
    )
    .unwrap_or_else(|error| std::panic!("could not install the host encoder: {error}"));
  context
    .eval(boa_engine::Source::from_bytes(TEXT_ENCODER_SHIM))
    .unwrap_or_else(|error| std::panic!("the host API shim does not evaluate: {error}"));
}

/// `TextEncoder.prototype.encode`, backed by the host's own UTF-8 conversion.
fn host_utf8_encode(
  _this: &boa_engine::JsValue,
  arguments: &[boa_engine::JsValue],
  context: &mut boa_engine::Context,
) -> boa_engine::JsResult<boa_engine::JsValue> {
  let text = arguments
    .first()
    .cloned()
    .unwrap_or_default()
    .to_string(context)?;
  // Lossy is the CONFORMANT choice here, not a shortcut: the WHATWG encoding
  // standard replaces an unpaired surrogate with U+FFFD, which is exactly what
  // this conversion does. Refusing would make the shim stricter than the API it
  // stands in for.
  let utf8 = text.to_std_string_lossy().into_bytes();
  boa_engine::object::builtins::JsUint8Array::from_iter(utf8, context)
    .map(|array| boa_engine::JsValue::from(array))
}
