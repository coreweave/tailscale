// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Type definitions for types generated by the esbuild build
 * process.
 */

declare module "*.wasm" {
  const path: string
  export default path
}

declare const DEBUG: boolean
