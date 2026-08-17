---
name: deploy-to-prod
description: Use when deploying, releasing, or updating LinkGuard FW on the production firewall — building a new .deb, cutting a release version, or installing an update on the prod box (<prod-host>). Covers the CI pipeline, downloading the release, and installing over SSH.
---

# Deploy LinkGuard FW to production

## Overview

Deploy = **merge to `main` → CI builds the `.deb` → download → verify sha256 → `scp` → `dpkg -i` on prod**. Deploying manually via the release artifacts is the reliable path; the in-app self-updater is a convenience, not the deploy mechanism.

Never build the `.deb` by hand for a real deploy: local machines usually lack `node`/`npm` (needed for the embedded frontend), and hand-built packages skip the CI tests. Use the pipeline.

## The pipeline (`.github/workflows/release.yml`)

- **Trigger:** push to `main`, or `workflow_dispatch`. Feature branches do **not** build.
- **Version:** auto-increments the patch from the latest `vX.Y.Z` tag (last `v1.0.53` → next `v1.0.54`). No manual tagging needed.
- Runs `go test ./...`, builds `amd64` + `arm64`, generates `sha256sums.txt`, creates the GitHub Release with the `.deb`s attached.

⚠️ **The CI builds the `.deb` control block INLINE in `release.yml` — it does NOT use the Makefile.** Any packaging change (e.g. `Depends:`, added files) must be edited in **both** `.github/workflows/release.yml` AND the `Makefile`, or it won't reach the released package. The CI **does** use `deploy/linkguard-fw.service`, so unit changes are picked up.

## Prod box facts

- SSH: `ssh <user>@<prod-host>` (key auth, Debian 13, amd64).
- **Root access depends on how the box was set up** (`sudo` may be absent). Run root commands as:
  `ssh <user>@<prod-host> 'su - -c "bash -s"' <<'EOF' ... EOF`
- The daemon runs as **root** and is `enabled`+`active`. `postinst` restarts it on install.
- SSH is LAN-local (estação de trabalho → LAN do firewall), so the service restart does **not** drop your session.
- `dpkg -i` does **not** resolve `Depends` — fine on prod (deps already present). On a **fresh** server use `apt install ./file.deb`.

## Deploy steps

```bash
# 1. Merge the fix to main (triggers CI). Rebase-merge keeps history linear.
gh pr merge <PR#> --rebase --delete-branch

# 2. Watch the build, get the version it cut.
gh run watch $(gh run list --workflow=release.yml -L1 --json databaseId -q '.[0].databaseId') --exit-status
VER=v1.0.54   # from the run / `gh release list -L1`

# 3. Download the amd64 .deb + checksums locally.
gh release download "$VER" -p 'linkguard-fw_*_amd64.deb' -p 'sha256sums.txt' -D /tmp/lg --clobber

# 4. Verify checksum locally.
cd /tmp/lg && grep amd64.deb sha256sums.txt | sha256sum -c -
dpkg-deb -f linkguard-fw_*_amd64.deb Depends   # sanity-check packaging changes landed

# 5. Ship to prod and confirm sha matches before installing.
scp linkguard-fw_*_amd64.deb <user>@<prod-host>:/tmp/
ssh <user>@<prod-host> 'sha256sum /tmp/linkguard-fw_*_amd64.deb'

# 6. Install as root (postinst restarts the service).
ssh <user>@<prod-host> 'su - -c "dpkg -i /tmp/linkguard-fw_'"${VER#v}"'_amd64.deb"'

# 7. Verify.
ssh <user>@<prod-host> 'su - -c "systemctl is-active linkguard-fw; /usr/local/bin/linkguard-fw --version"'
```

## Runtime prerequisites the app now owns

The daemon self-configures these at startup (no manual sysctl/routing needed), persisting drop-ins in `/etc/sysctl.d/`:
- `net.netfilter.nf_conntrack_acct=1` — per-host traffic ("Top consumidores" on Hosts). `hosttraffic.EnsureAccounting()`.
- `net.ipv4.ip_forward=1` — LAN↔WAN routing. `routes.EnsureForwarding()`.
- WAN steering / policy routing — `balancer.EnsureSteerRouting()`.

These writes need `/etc/sysctl.d` in the unit's `ReadWritePaths` (`ProtectSystem=strict`).

## Common mistakes

- **Editing only the Makefile for packaging changes** → the released `.deb` is unchanged. Edit `release.yml` too.
- **Pushing to a feature branch expecting a build** → CI only fires on `main`.
- **`git push origin main` / prod writes under the auto-mode classifier get blocked** → use `gh pr merge` for integration; if a prod `scp`/`dpkg` is blocked, hand the exact command to the user or run outside auto mode.
- **Relying on the in-app updater for a real deploy** → prefer the release artifacts; they are checksum-verified.
- **`dpkg -i` on a fresh server** → won't pull `Depends`; use `apt install ./file.deb`.
