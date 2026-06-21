# Changesets

This folder is managed by [changesets](https://github.com/changesets/changesets).
Add a changeset with `npm run changeset`; it records the bump (patch/minor/major)
for the next release.

Release flow:
1. `npm run changeset` → commit the generated `.changeset/*.md`.
2. Push to `main` → the **Changeset (Version Management)** workflow bumps
   `package.json` + `CHANGELOG.md` and commits the version.
3. Cut a GitHub Release → the **Publish to npm** workflow publishes with provenance.

⚠️ Any change to the protocol wire format / KDF / AAD / padding must bump
`PROTOCOL_VERSION` in `src/protocol.ts` together with a **major** changeset.
