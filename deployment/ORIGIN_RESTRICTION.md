# Origin restriction: the site is reachable only through Cloudflare

Proxied DNS hides the origin from ordinary visitors; it does not stop anyone from
finding the address and connecting to it directly. Both deployed `.htaccess` files
therefore refuse any request that does not carry the header Cloudflare adds:

```apache
RewriteCond %{HTTP:X-Origin-Secret} !^__CF_ORIGIN_SECRET__$
RewriteRule ^ - [F,L]
```

`__CF_ORIGIN_SECRET__` is a placeholder. The real value is inserted at build time
and is never committed.

| File | Protects |
| --- | --- |
| `frontend/public/.htaccess` | the static site and the SPA rewrite at the web root |
| `api/.htaccess` | everything under `/api/` |

Both are required. mod_rewrite rules in a parent directory are **not** inherited by
a child directory that has its own `.htaccess`, so a rule at the web root does not
apply to `/api/` at all.

## Where the value comes from

Cloudflare adds it: Rules, Transform Rules, Modify Request Header, action
**Set static**. `Set static` overwrites a visitor-supplied value, so a client
cannot supply its own. The string must match the deployed `.htaccess` exactly and
may only use `A-Z a-z 0-9 - _` (it is compared inside a PCRE, where `+ / = . $`
would break or weaken the match).

At build time, `deployment/stamp-origin-secret.mjs` reads it from
`THREATPULSE_ORIGIN_SECRET` (or `THREATPULSE_ORIGIN_SECRET_FILE`, or
`threatpulse-secrets/origin-secret.env`) and writes it into
`frontend/dist/.htaccess` and `deployment/build/api/.htaccess`. Upload those; never
upload the tracked templates, which still contain the placeholder.

```bash
cd frontend
npm run build            # builds, then stamps both artifacts
npm run stamp:origin     # re-stamps without rebuilding
npm run stamp:origin -- --check   # reports the source and targets, writes nothing
```

The build fails when the value is missing, malformed, or when `dist/` was never
built. That is deliberate: an artifact that cannot enforce the rule must not look
deployable.

## Two exemptions

- `/.well-known/acme-challenge/` skips the header check so certificate renewal can
validate straight against the origin.
- Both files also deny dot-files (`^\.(?!well-known)`) so the `.htaccess` holding
the value can never be served, while `/.well-known/` stays reachable.

## Verify

```bash
# through Cloudflare: 200
curl -sS -o /dev/null -w "%{http_code}\n" https://threatpulse.iliadis.net/

# direct to the origin, no header: 403
curl -ksS -o /dev/null -w "%{http_code}\n" --resolve threatpulse.iliadis.net:443:ORIGIN_IP https://threatpulse.iliadis.net/

# direct to the origin, with the header: 200
curl -ksS -o /dev/null -w "%{http_code}\n" -H "X-Origin-Secret: VALUE" --resolve threatpulse.iliadis.net:443:ORIGIN_IP https://threatpulse.iliadis.net/
```

The last two are the ones that matter: a 403 alone could be the network, not the rule.

## Limits

This is a shared static secret. It proves knowledge of a value, not that the caller
is Cloudflare. Anyone who learns it reaches the origin until it is rotated. The
stronger layers, in order, are an origin allowlist of Cloudflare address ranges and
Cloudflare Authenticated Origin Pulls (mTLS); the header rule stays underneath both.
Cloudflare SSL mode must be Full (strict), otherwise the header crosses the public
internet in clear text.

Rotation: generate a new value (`openssl rand -hex 32`), update the Cloudflare rule
and the local env file, rebuild, upload both artifacts. The edge and the origin
disagree for the few minutes between those steps, so the site returns 403 until
they match.