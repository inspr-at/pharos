import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const publicMountSource = readFileSync(
  new URL("../../crates/pharosd/src/public_mount.rs", import.meta.url),
  "utf8",
);

const beginMarker = "window.pharosPublicPath=function(p){{";
const endMarker = "}};</script>";

const begin = publicMountSource.indexOf(beginMarker);
assert.notEqual(
  begin,
  -1,
  "public_mount.rs must contain the production pharosPublicPath script opener",
);
assert.equal(
  publicMountSource.indexOf(beginMarker, begin + 1),
  -1,
  "public_mount.rs must contain exactly one pharosPublicPath script",
);

const end = publicMountSource.indexOf(endMarker, begin);
assert.notEqual(
  end,
  -1,
  "public_mount.rs pharosPublicPath script must close with the expected shape",
);

const rustEscaped = publicMountSource.slice(begin, end + "}};".length);
const pharosPublicPathSource = rustEscaped.replaceAll("{{", "{").replaceAll("}}", "}");

assert.match(
  pharosPublicPathSource,
  /^window\.pharosPublicPath=function\(p\)\{var b=document\.querySelector\('meta\[name="pharos-public-base-path"\]'\)/,
  "extracted pharosPublicPath must match the production helper shape",
);
assert.ok(
  pharosPublicPathSource.endsWith("};"),
  "extracted pharosPublicPath must end with a statement terminator",
);
assert.equal(
  pharosPublicPathSource.includes("{{") || pharosPublicPathSource.includes("}}"),
  false,
  "extracted pharosPublicPath must not retain Rust format escapes",
);

export { pharosPublicPathSource };
