#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""webcheck-mcp — 站点健康 / SEO / DNS / SSL 审计 MCP 服务器（给 AI Agent 用）

解决的问题：Agent 在「构建/部署/管理网站」后，无法凭训练知识判断——
  1. 站点是否真的在线？状态码 / 重定向链是什么？
  2. SSL 证书是否即将过期？签发者是谁？
  3. SEO 标签（title / meta / canonical / Open Graph）是否写对？
  4. 页面有没有断链、图片缺 alt、缺安全响应头？
  5. DNS 记录（A/AAAA/MX/TXT/NS/CNAME）是否已生效？

这些是「实时数据 + 计算 + 验证」类能力，模型无法在脑中推算，必须由工具打通。
纯标准库实现（urllib / socket / ssl / http.server），零第三方依赖。

用法：
  python3 webcheck_mcp.py            # stdio 模式（Claude Desktop / WorkBuddy / Cursor 等）
  python3 webcheck_mcp.py --http 8975 # streamable HTTP 模式（Smithery / 官方 registry 托管接入）

协议：MCP (JSON-RPC 2.0)，protocol version 2024-11-05。
"""
import json, re, sys, datetime, time, socket, ssl as ssl_mod, urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from html.parser import HTMLParser

PROTOCOL_VERSION = '2024-11-05'
UA = {'User-Agent': 'webcheck-mcp/1.0 (site audit; contact niebingyu@qq.com)',
      'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8'}
CACHE = {}
CACHE_TTL = 600  # 10 分钟缓存（DNS / robots / sitemap 等）

# ---------- 通用工具 ----------
def fetch(url, timeout=15, headers=None, max_bytes=3_000_000):
    """GET 一个 URL，返回 (状态码, 最终URL, 响应头dict, 字节流body, 重定向链)。
    4xx/5xx 不抛异常，而是返回状态码供审计判断。"""
    h = dict(UA)
    if headers:
        h.update(headers)
    redirects = []

    class _R(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            redirects.append({'code': code, 'to': newurl})
            return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, hdrs, newurl)

    opener = urllib.request.build_opener(_R())
    req = urllib.request.Request(url, headers=h)
    try:
        resp = opener.open(req, timeout=timeout)
        code = resp.getcode()
        final_url = resp.geturl()
        rheaders = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(max_bytes)
        return code, final_url, rheaders, body, redirects
    except urllib.error.HTTPError as e:
        # 4xx/5xx 也算审计结果，不视为崩溃
        body = b''
        try:
            body = e.read(max_bytes)
        except Exception:
            pass
        return e.code, e.geturl() or url, {k.lower(): v for k, v in e.headers.items()}, body, redirects
    except Exception as e:
        return None, url, {}, b'', [{'code': None, 'to': 'ERROR: %r' % e}]

def cached(key, fn):
    now = time.time()
    if key in CACHE and now - CACHE[key][0] < CACHE_TTL:
        return CACHE[key][1]
    val = fn()
    CACHE[key] = (now, val)
    return val

# ---------- SSL 证书 ----------
def parse_cert_date(s):
    """把 openssl 风格的 'Oct 1 00:00:00 2026 GMT' 解析为 datetime。"""
    if not s:
        return None
    s = re.sub(r'\s+', ' ', str(s).replace(' GMT', '').strip())
    for fmt in ('%b %d %H:%M:%S %Y', '%b %d %H:%M:%S %Y %Z'):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None

def _dn_to_dict(dn):
    """把 getpeercert() 返回的 subject/issuer（嵌套元组）拍平成 {'commonName': 'x', ...}。"""
    out = {}
    for item in dn or ():
        if isinstance(item, (tuple, list)) and len(item) == 1 and isinstance(item[0], (tuple, list)):
            item = item[0]
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            out[item[0]] = item[1]
    return out

def ssl_cert_info(host, port=443, timeout=10):
    """返回证书的 到期/生效/签发者/主体/域名列表。"""
    ctx = ssl_mod.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        return {'error': repr(e)}
    if not cert:
        return {'error': 'empty cert'}
    not_after = parse_cert_date(cert.get('notAfter', ''))
    not_before = parse_cert_date(cert.get('notBefore', ''))
    days = None
    if not_after:
        days = (not_after.date() - datetime.date.today()).days
    san = cert.get('subjectAltName', []) or []
    names = []
    for entry in san:
        # entry 可能是 ('DNS', 'x.com')，也可能是嵌套结构
        if isinstance(entry, (tuple, list)):
            if len(entry) == 1 and isinstance(entry[0], (tuple, list)):
                entry = entry[0]
            if len(entry) >= 2 and entry[0] == 'DNS':
                names.append(entry[1])
    return {
        'host': host,
        'issuer': _dn_to_dict(cert.get('issuer', ())),
        'subject': _dn_to_dict(cert.get('subject', ())),
        'not_before': str(cert.get('notBefore', '')),
        'not_after': str(cert.get('notAfter', '')),
        'days_until_expiry': days,
        'expired': bool(days is not None and days < 0),
        'san_domains': names,
    }

# ---------- DNS（通过 Google / Cloudflare DoH，纯 HTTP+JSON） ----------
DNS_TYPE = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'NS': 2, 'SOA': 6, 'PTR': 12}
DNS_TYPE_NAME = {v: k for k, v in DNS_TYPE.items()}

def dns_lookup(domain, types=('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME')):
    """通过 DoH 查询 DNS 记录。支持多类型，返回结构化结果。"""
    results = {}
    for t in types:
        t = t.upper()
        if t not in DNS_TYPE:
            results[t] = {'error': 'unsupported type'}
            continue
        try:
            # 首选 Google DoH，失败回落 Cloudflare DoH
            data = None
            for endpoint in ('https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'):
                try:
                    q = endpoint + '?' + urllib.parse.urlencode({'name': domain, 'type': t})
                    hdr = dict(UA)
                    if 'cloudflare' in endpoint:
                        hdr['Accept'] = 'application/dns-json'
                    req = urllib.request.Request(q, headers=hdr)
                    with urllib.request.urlopen(req, timeout=10) as r:
                        data = json.loads(r.read().decode('utf-8', 'ignore'))
                    break
                except Exception:
                    continue
            if data is None:
                results[t] = {'error': 'doh unreachable'}
                continue
            status = data.get('Status', -1)
            answer = data.get('Answer', [])
            records = []
            for a in answer:
                if a.get('type') == DNS_TYPE[t]:
                    rec = {'name': a.get('name'), 'ttl': a.get('TTL'), 'value': a.get('data')}
                    # MX / SOA 附带优先级
                    if t == 'MX':
                        parts = a.get('data', '').split(' ')
                        if len(parts) >= 2 and parts[0].isdigit():
                            rec['priority'] = int(parts[0])
                            rec['value'] = ' '.join(parts[1:])
                    records.append(rec)
            results[t] = {'status': status, 'status_ok': status == 0, 'records': records}
        except Exception as e:
            results[t] = {'error': repr(e)}
    return {'domain': domain, 'types': list(results.keys()), 'resolved': results}

# ---------- HTML 解析（提取 SEO 元信息 / 链接 / 图片 / 标题层级） ----------
_META_RE = re.compile(r'<meta\b[^>]*>', re.I)
_ATTR_RE = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))')

def _parse_meta(html):
    """解析 <meta> 标签，返回 dict。"""
    out = {}
    for m in _META_RE.findall(html):
        attrs = {}
        for k, _full, dq, sq, bare in _ATTR_RE.findall(m):
            attrs[k.lower()] = (dq or sq or bare or '').strip()
        key = attrs.get('name') or attrs.get('property') or attrs.get('http-equiv')
        if key and 'content' in attrs:
            out[key.lower()] = attrs['content']
    return out

_LINK_RE = re.compile(r'<a\b[^>]*href\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))[^>]*>', re.I)
_IMG_RE = re.compile(r'<img\b[^>]*>', re.I)
_H_RE = re.compile(r'<h([1-6])\b[^>]*>(.*?)</h\1>', re.I | re.S)

def _strip_tags(s):
    return re.sub(r'<[^>]+>', '', s).strip()

def _resolve(base, href):
    return urllib.parse.urljoin(base, href)

def analyze_html(html, final_url):
    """提取 SEO/内容结构/链接/图片信息。"""
    meta = _parse_meta(html)
    title = ''
    tm = re.search(r'<title\b[^>]*>(.*?)</title>', html, re.I | re.S)
    if tm:
        title = _strip_tags(tm.group(1))
    base_host = urllib.parse.urlparse(final_url).netloc

    images, missing_alt = 0, 0
    for img in _IMG_RE.findall(html):
        images += 1
        if not re.search(r'\balt\s*=', img, re.I):
            missing_alt += 1

    headings = {}
    for lv, txt in _H_RE.findall(html):
        headings.setdefault('h' + lv, []).append(_strip_tags(txt)[:120])

    internal, external, total = 0, 0, 0
    links = []
    for _full, dq, sq, bare in _LINK_RE.findall(html):
        href = (dq or sq or bare or '').strip()
        if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            continue
        absu = _resolve(final_url, href)
        host = urllib.parse.urlparse(absu).netloc
        total += 1
        if host == base_host or not host:
            internal += 1
        else:
            external += 1
        if len(links) < 200:
            links.append({'href': absu, 'internal': host == base_host or not host})

    return {
        'title': title,
        'meta_description': meta.get('description', ''),
        'canonical': meta.get('canonical', ''),
        'robots': meta.get('robots', ''),
        'open_graph': {k: v for k, v in meta.items() if k.startswith('og:')},
        'twitter_card': {k: v for k, v in meta.items() if k.startswith('twitter:')},
        'headings': headings,
        'images': {'total': images, 'missing_alt': missing_alt},
        'links': {'total': total, 'internal': internal, 'external': external, 'sample': links},
    }

SECURITY_HEADERS = [
    'strict-transport-security', 'content-security-policy', 'x-frame-options',
    'x-content-type-options', 'referrer-policy', 'x-xss-protection',
    'permissions-policy',
]

# ---------- 工具 1：check_site ----------
def tool_check_site(args):
    url = (args.get('url') or '').strip()
    if not url:
        return {'error': 'missing url'}
    if '://' not in url:
        url = 'http://' + url  # 未带协议时默认 http
    start = time.time()
    code, final_url, rheaders, body, redirects = fetch(url)
    elapsed_ms = int((time.time() - start) * 1000)
    if code is None:
        return {'url': url, 'error': 'unreachable', 'redirects': redirects, 'elapsed_ms': elapsed_ms}

    charset = 'utf-8'
    ct = rheaders.get('content-type', '')
    m = re.search(r'charset=([\w-]+)', ct)
    if m:
        charset = m.group(1)
    html = body.decode(charset, 'ignore')

    host = urllib.parse.urlparse(final_url).netloc
    scheme = urllib.parse.urlparse(final_url).scheme

    result = {
        'url': url,
        'final_url': final_url,
        'status_code': code,
        'ok': 200 <= code < 400,
        'redirects': redirects,
        'elapsed_ms': elapsed_ms,
        'content_type': ct,
        'page_size_bytes': len(body),
        'server': rheaders.get('server', ''),
        'security_headers': {h: rheaders.get(h, None) for h in SECURITY_HEADERS},
        'security_missing': [h for h in SECURITY_HEADERS if not rheaders.get(h)],
    }

    # SSL（仅 https）
    if scheme == 'https' and host:
        result['ssl'] = cached('ssl:' + host, lambda h=host: ssl_cert_info(h))

    # robots.txt / sitemap.xml
    base_origin = scheme + '://' + host
    def _check_robots():
        c, _, _, b, _ = fetch(base_origin + '/robots.txt')
        return {'status': c, 'found': bool(c and 200 <= c < 400)}
    def _check_sitemap():
        c, _, _, b, _ = fetch(base_origin + '/sitemap.xml')
        return {'status': c, 'found': bool(c and 200 <= c < 400)}
    try:
        result['robots_txt'] = cached('robots:' + host, _check_robots)
    except Exception:
        result['robots_txt'] = {'found': False}
    try:
        result['sitemap_xml'] = cached('sitemap:' + host, _check_sitemap)
    except Exception:
        result['sitemap_xml'] = {'found': False}

    # SEO / 内容结构
    result['seo'] = analyze_html(html, final_url)
    return result

# ---------- 工具 2：check_ssl ----------
def tool_check_ssl(args):
    host = (args.get('host') or '').strip()
    if not host:
        return {'error': 'missing host'}
    host = host.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    return ssl_cert_info(host)

# ---------- 工具 3：dns_lookup ----------
def tool_dns(args):
    domain = (args.get('domain') or '').strip()
    if not domain:
        return {'error': 'missing domain'}
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    types = args.get('types') or ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    return dns_lookup(domain, types)

# ---------- 工具清单（MCP 元数据） ----------
TOOLS = [
    {'name': 'check_site',
     'description': '全面审计一个 URL：HTTP 状态码、重定向链、响应耗时、SSL 证书（到期天数/签发者/域名）、安全响应头（HSTS/CSP/X-Frame 等）、robots.txt/sitemap.xml、SEO 元信息（title/meta/canonical/Open Graph/Twitter Card）、图片 alt、标题层级、内外部链接统计。给构建/部署/管理网站的 Agent 做上线验证与体检。',
     'inputSchema': {'type': 'object', 'properties': {
         'url': {'type': 'string', 'description': '要审计的站点 URL（可省略 http/https 前缀，默认 http）'}},
         'required': ['url']}},
    {'name': 'check_ssl',
     'description': '单独查询一个域名的 SSL/TLS 证书：签发者、主体、生效/到期时间、剩余有效天数、是否已过期、SAN 域名列表。用于证书到期监控与排查。',
     'inputSchema': {'type': 'object', 'properties': {
         'host': {'type': 'string', 'description': '域名或主机名，如 example.com'}},
         'required': ['host']}},
    {'name': 'dns_lookup',
     'description': '通过 DoH（Google/Cloudflare 双源回落）查询域名 DNS 记录：A / AAAA / MX（含优先级）/ NS / TXT / CNAME / SOA / PTR。用于验证 DNS 配置是否生效、排查解析问题。',
     'inputSchema': {'type': 'object', 'properties': {
         'domain': {'type': 'string', 'description': '要查询的域名，如 example.com'},
         'types': {'type': 'array', 'items': {'type': 'string'},
                   'description': '记录类型，默认 ["A","AAAA","MX","NS","TXT","CNAME"]'}},
         'required': ['domain']}},
]

# ---------- MCP 协议核心 ----------
def handle_request(req):
    method = req.get('method', '')
    rid = req.get('id')
    def ok(result):
        return {'jsonrpc': '2.0', 'id': rid, 'result': result}
    def err(code, message):
        return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': code, 'message': message}}
    if method == 'initialize':
        return ok({'protocolVersion': PROTOCOL_VERSION,
                   'capabilities': {'tools': {}},
                   'serverInfo': {'name': 'webcheck-mcp', 'version': '1.0.0'}})
    elif method == 'notifications/initialized':
        return None
    elif method == 'ping':
        return ok({})
    elif method == 'tools/list':
        return ok({'tools': TOOLS})
    elif method == 'tools/call':
        name = req.get('params', {}).get('name', '')
        args = req.get('params', {}).get('arguments', {}) or {}
        try:
            if name == 'check_site':
                data = tool_check_site(args)
            elif name == 'check_ssl':
                data = tool_check_ssl(args)
            elif name == 'dns_lookup':
                data = tool_dns(args)
            else:
                return err(-32601, 'unknown tool: ' + name)
            return ok({'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=False, indent=1)}], 'isError': False})
        except Exception as e:
            return err(-32000, repr(e))
    elif rid is not None:
        return err(-32601, 'method not found: ' + method)
    return None

# ---------- stdio 模式 ----------
def main_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle_request(req)
        if resp:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + '\n')
            sys.stdout.flush()

# ---------- HTTP 模式（streamable HTTP transport） ----------
class MCPHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, Authorization, Last-Event-ID')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, DELETE')
        self.send_header('Access-Control-Expose-Headers', 'Mcp-Session-Id')

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_GET(self):
        self.send_response(200); self._cors()
        self.send_header('Content-Type', 'application/json'); self.end_headers()
        self.wfile.write(json.dumps({'service': 'webcheck-mcp', 'transport': 'streamable-http', 'ok': True}).encode())

    def do_DELETE(self):
        self.send_response(200); self._cors(); self.end_headers()

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(n)
        try:
            req = json.loads(body.decode('utf-8'))
        except Exception:
            self.send_response(400); self._cors(); self.end_headers(); return
        resp = handle_request(req)
        accept = self.headers.get('Accept', 'application/json')
        self.send_response(200); self._cors()
        if 'text/event-stream' in accept and resp is not None:
            self.send_header('Content-Type', 'text/event-stream'); self.end_headers()
            self.wfile.write(('data: ' + json.dumps(resp, ensure_ascii=False) + '\n\n').encode())
        else:
            self.send_header('Content-Type', 'application/json'); self.end_headers()
            if resp is not None:
                self.wfile.write(json.dumps(resp, ensure_ascii=False).encode())

    def log_message(self, *a):
        pass

def main_http(port):
    print('webcheck-mcp HTTP server listening on 127.0.0.1:%d' % port, flush=True)
    HTTPServer(('127.0.0.1', port), MCPHandler).serve_forever()

if __name__ == '__main__':
    if '--http' in sys.argv:
        i = sys.argv.index('--http')
        port = int(sys.argv[i + 1]) if len(sys.argv) > i + 1 else 8975
        main_http(port)
    else:
        main_stdio()
