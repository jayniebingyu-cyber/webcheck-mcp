# webcheck-mcp

**Website health, SEO, SSL & DNS intelligence for AI agents. Zero dependencies, pure Python stdlib.**

Built for agents that build, deploy, or manage websites — the moment an agent ships a site, it needs to *verify* the result, and it cannot do that from training data. This server gives it live, computed answers: is it up, is the SSL expiring, are the SEO tags right, are there broken links, has DNS propagated.

## Tools

| Tool | What it gives the agent |
|---|---|
| `check_site` | Full audit of a URL: HTTP status + redirect chain, response time, SSL certificate (issuer / expiry days / SAN), security headers (HSTS/CSP/X-Frame-Options/…), robots.txt & sitemap.xml presence, SEO meta (title / description / canonical / Open Graph / Twitter Card), image alt coverage, heading hierarchy, and internal/external link stats |
| `check_ssl` | Standalone SSL/TLS certificate lookup: issuer, subject, valid-from/to, days until expiry, expired flag, SAN domains — for cert-expiry monitoring and debugging |
| `dns_lookup` | DNS records via DoH (Google + Cloudflare fallback): A / AAAA / MX (with priority) / NS / TXT / CNAME / SOA / PTR — to confirm DNS config has actually propagated |

## Why this exists

- **The model can't verify live state.** "Is my site live?", "Is my cert about to expire?", "Are my DNS records correct?" are *live data + compute* questions — a model has no way to answer them without a tool that actually hits the network.
- **One command, no browser needed.** Agents routinely shell out to `curl` + `openssl` + ad-hoc scripts; this returns structured JSON in a single call, with graceful degradation (any single check failing doesn't break the whole audit).
- **Cross-border reachability.** The hosted version runs on a Singapore node that can reach both mainland-China-hosted and global sites, so an agent auditing a China-hosted site from overseas (or vice-versa) gets a real answer instead of a timeout.

## Quick start

Requires Python 3.8+. No pip install needed.

### Claude Desktop / WorkBuddy / Cursor (`mcp.json`)

```json
{
  "mcpServers": {
    "webcheck": {
      "command": "python",
      "args": ["/absolute/path/to/server.py"]
    }
  }
}
```

Then ask your agent: *"Run a site check on my new site"* or *"Is my SSL cert about to expire?"*.

### Example tool calls

```json
{"name": "check_site", "arguments": {"url": "https://example.com"}}
{"name": "check_ssl", "arguments": {"host": "example.com"}}
{"name": "dns_lookup", "arguments": {"domain": "example.com", "types": ["A", "MX", "TXT"]}}
```

## Hosted API (no install, works from any network)

Don't want to run it yourself? A hosted version runs 24/7 on our Singapore server — one HTTP GET, JSON back:

```
GET http://43.160.199.215/webcheck/v1/check?url=https://example.com&key=YOUR_KEY
GET http://43.160.199.215/webcheck/v1/ssl?host=example.com&key=YOUR_KEY
GET http://43.160.199.215/webcheck/v1/dns?domain=example.com&types=A,MX&key=YOUR_KEY
GET http://43.160.199.215/webcheck/v1/health
```

30-day access key: **$9** → https://niebingyu.gumroad.com/l/webcheck-api

## Notes

- 10-minute in-memory cache for DNS / robots / sitemap lookups; polite to upstreams.
- All data is gathered from public endpoints for diagnostics; respect each target's terms.
- Protocol: MCP over stdio, JSON-RPC 2.0, protocol version 2024-11-05. Also supports streamable HTTP (`server.py --http <port>`).

## License

MIT
