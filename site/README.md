# site/ — antharmaya.com/tools/stallwatch

One HTML file. No build step, no framework, no bundler, no webfonts, and no
external requests of any kind — the same constraint the binary is held to, for
the same reason: a page that argues for zero dependencies should not ship a
crate graph of its own.

```
public/
  index.html    the whole site
  install.sh    copy of ../install.sh, so `curl | sh` needs no second host
```

## Deploy

Static assets on Cloudflare Workers. No Worker script is involved.

```sh
cd site
npx wrangler deploy
```

The path route `antharmaya.com/tools/stallwatch*` is declared in `wrangler.jsonc`
and must exist as a zone on the account first.

## The installer copy

`public/install.sh` is a copy of the canonical `install.sh` at the repo root so
the one-liner can be served from this domain. Two copies of a script that
installs binaries is exactly the thing that drifts silently, so CI diffs them
and fails the build if they diverge. Edit the root copy, then:

```sh
cp ../install.sh public/install.sh
```

## Editing

Open `public/index.html` directly, or serve it if you want to check the load
animation and clipboard button, both of which need a real origin:

```sh
python3 -m http.server 8788 --directory public
```
