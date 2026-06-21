---
"@alternatefutures/e2ee": patch
---

Fix dual-package exports for CommonJS / node16 consumers. Each subpath now uses
per-condition types (`import` → `.d.ts`, `require` → `.d.cts`) so a CJS consumer
under `moduleResolution: node16/nodenext` (the `acc` CLI) resolves the package
without TS1479. Also expose `./package.json`.
