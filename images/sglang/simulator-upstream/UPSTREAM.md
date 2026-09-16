# SGLang Simulator source

This directory contains an exact copy of `tools/sglang-simulator` from SGLang
pull request 33824 at commit
`5e6af31ae3fe8d95f83bab8c78e4db834142b313`.

`UPSTREAM.md` and `LICENSE` provide local provenance and license information.

Source: <https://github.com/sgl-project/sglang/pull/33824>

The simulator is not on the normal Python path. Production continues to use
the normal SGLang command. The staging manifest adds this directory to
`PYTHONPATH` and starts the separate simulator entry point.

The upstream Apache-2.0 license is in `LICENSE`.
