/* STATIC Proxy (AGPL-3.0)

Copyright (C) 2025 - 404 Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

use std::{
    io::sink,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use anyhow::{anyhow, Result as AnyResult};
use minify_js::{minify, Session, TopLevelMode};
use swc_core::{
    common::{
        comments::SingleThreadedComments,
        errors::{Handler, HandlerFlags, EmitterWriter},
        sync::Lrc,
        FileName, Globals, Mark, SourceMap, GLOBALS,
    },
    ecma::{
        ast::EsVersion,
        codegen::{text_writer::JsWriter, Config as CodegenConfig, Emitter},
        minifier::{
            optimize,
            option::{ExtraOptions, MinifyOptions},
        },
        parser::{EsConfig, Parser, StringInput, Syntax},
    },
};
use tracing::warn;

#[derive(Clone)]
pub struct ScriptBundle {
    pub boot: Arc<str>,
    pub shim: Arc<str>,
    pub config_layer: Arc<str>,
    pub spoofing: Arc<str>,
    pub behavioral_noise: Arc<str>,
}

impl ScriptBundle {
    pub fn load() -> Self {
        Self {
            boot: minify_asset("0bootstrap_v4.js", include_str!("../assets/js/0bootstrap_v4.js")),
            shim: minify_asset("1globals_shim_v4.js", include_str!("../assets/js/1globals_shim_v4.js")),
            config_layer: minify_asset("config_layer_v3.js", include_str!("../assets/js/config_layer_v3.js")),
            spoofing: minify_asset("2fingerprint_spoof_v4.js", include_str!("../assets/js/2fingerprint_spoof_v4.js")),
            behavioral_noise: minify_asset("behavioral_noise_v1.js", include_str!("../assets/js/behavioral_noise_v1.js")),
        }
    }
}

fn minify_asset(label: &str, source: &str) -> Arc<str> {
    let session = Session::new();
    let mut output = Vec::with_capacity(source.len());
    let minify_out = catch_unwind(AssertUnwindSafe(|| {
        minify(&session, TopLevelMode::Global, source.as_bytes(), &mut output)
    }));

    match minify_out {
        Ok(Ok(())) => match String::from_utf8(output) {
            Ok(minified) => Arc::from(minified),
            Err(err) => {
                warn!(asset = label, ?err, "failed to decode minified JS; attempting swc fallback");
                fallback_minify(label, source)
            }
        },
        Ok(Err(err)) => {
            warn!(asset = label, %err, "minify-js failed; attempting swc fallback");
            fallback_minify(label, source)
        }
        Err(_) => {
            warn!(asset = label, "minify-js panicked; attempting swc fallback");
            fallback_minify(label, source)
        }
    }
}

fn fallback_minify(label: &str, source: &str) -> Arc<str> {
    match minify_with_swc(label, source) {
        Ok(minified) => Arc::from(minified),
        Err(err) => {
            warn!(asset = label, ?err, "swc fallback failed; injecting original content");
            Arc::from(source.to_owned())
        }
    }
}

fn minify_with_swc(label: &str, source: &str) -> AnyResult<String> {
    let cm: Lrc<SourceMap> = Default::default();
    let fm = cm.new_source_file(FileName::Custom(label.into()), source.into());

    let handler = Handler::with_emitter_and_flags(
        Box::new(EmitterWriter::new(
            Box::new(sink()),
            Some(cm.clone()),
            false,
            false,
        )),
        HandlerFlags {
            can_emit_warnings: true,
            dont_buffer_diagnostics: true,
            ..Default::default()
        },
    );

    let comments = SingleThreadedComments::default();

    GLOBALS.set(&Globals::new(), || {
        let mut parser = Parser::new(
            Syntax::Es(EsConfig {
                jsx: true,
                fn_bind: true,
                decorators: true,
                decorators_before_export: true,
                export_default_from: true,
                import_attributes: true,
                allow_super_outside_method: true,
                allow_return_outside_function: true,
                ..Default::default()
            }),
            StringInput::from(&*fm),
            Some(&comments),
        );

        let program = parser.parse_program().map_err(|err| {
            err.into_diagnostic(&handler).emit();
            anyhow!("swc failed to parse JS asset: {label}")
        })?;

        let unresolved_mark = Mark::fresh(Mark::root());
        let top_level_mark = Mark::fresh(Mark::root());

        let options = MinifyOptions {
            compress: None,
            mangle: None,
            ..Default::default()
        };

        let program = optimize(
            program,
            cm.clone(),
            Some(&comments),
            None,
            &options,
            &ExtraOptions {
                unresolved_mark,
                top_level_mark,
            },
        );

        let mut buf = Vec::with_capacity(source.len());
        {
            let writer = JsWriter::new(cm.clone(), "\n", &mut buf, None);
            let mut cfg = CodegenConfig::default();
            cfg.minify = true;
            cfg.target = EsVersion::Es2022;
            let mut emitter = Emitter {
                cfg,
                comments: None,
                cm: cm.clone(),
                wr: writer,
            };
            emitter
                .emit_program(&program)
                .map_err(|err| anyhow!("swc codegen failed for {label}: {err}"))?;
        }

        String::from_utf8(buf).map_err(Into::into)
    })
}
