"""Uploads vs real PHP: the same raw multipart bodies go to PHP's built-in
web server (php -S, via curl) and to miniPHP as a CGI request. Both run one
script that var_dumps $_POST and $_FILES and moves every upload into its own
folder; the dumps are compared (temp-file names masked -- they are random by
design) and every moved file is compared byte for byte.

    make && python3 tests/uploads_vs_php.py     (needs php and curl)
"""
import os, re, subprocess, sys, time, shutil, random, socket, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UP = tempfile.mkdtemp(prefix='uploads-vs-php-')
BIN = os.environ.get('BIN', os.path.join(ROOT, 'miniPHP'))
random.seed(5)

def body(parts, boundary='XyZBoundary123', crlf=b'\r\n', preamble=b'', epilogue=b'', close=True):
    out = preamble
    for p in parts:
        out += b'--' + boundary.encode() + crlf
        for h in p['h']: out += h + crlf
        out += crlf + p['d'] + crlf
    if close: out += b'--' + boundary.encode() + b'--' + crlf + epilogue
    return out

def field(name, val): return {'h': [b'Content-Disposition: form-data; name="' + name + b'"'], 'd': val}
def file(name, fname, data, ctype=b'application/octet-stream'):
    h = [b'Content-Disposition: form-data; name="' + name + b'"; filename="' + fname + b'"']
    if ctype is not None: h.append(b'Content-Type: ' + ctype)
    return {'h': h, 'd': data}

binblob = bytes(range(256)) * 4 + b'\r\n--XyZBoundary12\r\n\x00\x00end'
B = 'XyZBoundary123'; CT = 'multipart/form-data; boundary=' + B
cases = [
 ('one field',            CT, body([field(b'a', b'hello')])),
 ('fields + file',        CT, body([field(b'title', b'My doc'), file(b'doc', b'notes.txt', b'line1\nline2\n', b'text/plain'), field(b'after', b'x')])),
 ('binary file',          CT, body([file(b'bin', b'blob.bin', binblob)])),
 ('files[] multi',        CT, body([file(b'files[]', b'a.txt', b'AAA', b'text/plain'), file(b'files[]', b'b.txt', b'BBBB', b'text/plain')])),
 ('nested name',          CT, body([file(b'f[x][y]', b'n.txt', b'nested'), field(b'opts[]', b'1'), field(b'opts[]', b'2'), field(b'u[name]', b'bob')])),
 ('no file chosen',       CT, body([file(b'empty', b'', b'')])),
 ('too big (>2M)',        CT, body([file(b'big', b'big.bin', b'Z' * (2*1024*1024 + 10))])),
 ('MAX_FILE_SIZE',        CT, body([field(b'MAX_FILE_SIZE', b'10'), file(b'f', b'f.txt', b'x' * 20), file(b'g', b'g.txt', b'small')])),
 ('21 files',             CT, body([file(b'f%d' % i, b'%d.txt' % i, b'%d' % i) for i in range(21)])),
 ('path in filename',     CT, body([file(b'p1', b'../../evil.php', b'<?php'), file(b'p2', b'C:\\Users\\me\\photo.jpg', b'JPG'), file(b'p3', b'/etc/passwd', b'pw')])),
 ('quoted boundary',      'multipart/form-data; boundary="q-b=;x"', body([field(b'a', b'1')], boundary='q-b=;x')),
 ('preamble+epilogue',    CT, body([field(b'a', b'1')], preamble=b'This is a preamble\r\n', epilogue=b'trailing junk')),
 ('LF only',              CT, body([field(b'a', b'lf'), file(b'f', b'lf.txt', b'data')], crlf=b'\n')),
 ('truncated',            CT, body([field(b'a', b'1'), file(b'f', b'cut.txt', b'partial data')], close=False)[:-30]),
 ('part with no name',    CT, body([{'h': [b'Content-Disposition: form-data; filename="x.txt"'], 'd': b'x'}, field(b'ok', b'1')])),
 ('escaped quote',        CT, body([file(b'q', b'a\\"b.txt', b'q')])),
 ('dots/spaces in name',  CT, body([field(b'a.b c', b'1'), field(b' lead', b'2')])),
 ('no content-type',      CT, body([file(b'nt', b'nt.txt', b'no type', None)])),
 ('semicolon in quoted',  CT, body([field(b'a;b', b'semi')])),
 ('case: CONTENT-DISP',   CT, body([{'h': [b'content-disposition: FORM-DATA; NAME="Up"'], 'd': b'v'}])),
 ('filename= before name',CT, body([{'h': [b'Content-Disposition: form-data; filename="r.txt"; name="rev"'], 'd': b'r'}])),
 ('empty body',           CT, b''),
 ('missing boundary',     'multipart/form-data', body([field(b'a', b'1')])),
 ('urlencoded brackets',  'application/x-www-form-urlencoded', b'x[]=1&x[]=2&y[a][b]=3&z.w=4'),
]

def norm(s):
    s = s.replace('\r', '')
    # PHP's built-in server prints request-startup warnings into the page even
    # with display_errors=stderr; miniPHP sends them to stderr. Same data.
    s = re.sub(r'<br />\n<b>Warning</b>:.*?<br />\n', '', s)
    s = re.sub(r'string\(\d+\) "[^"]*/php[A-Za-z0-9]{6}"', 'TMPNAME', s)
    s = re.sub(r'^.*?\n\n', '', s, count=1, flags=re.S) if s.startswith('Status:') else s
    return s

def script(out):
    return ('<?php\nvar_dump($_POST);\nvar_dump($_FILES);\n'
            'foreach ($_FILES as $k => $f) {\n'
            '  if (is_array($f["tmp_name"])) {\n'
            '    foreach ($f["tmp_name"] as $i => $t) { if (!is_array($t) && $t != "") { move_uploaded_file($t, "%s/" . $k . "_" . $i); } }\n'
            '  } elseif ($f["tmp_name"] != "") { move_uploaded_file($f["tmp_name"], "%s/" . $k); }\n'
            '}\necho "end\\n";\n') % (out, out)

s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
docroot = os.path.join(UP, 'docroot'); os.makedirs(docroot)
srv = subprocess.Popen(['php', '-n', '-d', 'display_errors=stderr', '-S', '127.0.0.1:%d' % port, '-t', docroot], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.8)
match = differ = 0
try:
    for i, (name, ct, data) in enumerate(cases):
        po = os.path.join(UP, 'php%d' % i); mo = os.path.join(UP, 'mini%d' % i); os.makedirs(po); os.makedirs(mo)
        open(os.path.join(docroot, 'c%d.php' % i), 'w').write(script(po))
        open(os.path.join(UP, 'm%d.php' % i), 'w').write(script(mo))
        bf = os.path.join(UP, 'b%d' % i); open(bf, 'wb').write(data)
        p = subprocess.run(['curl', '-s', '--data-binary', '@' + bf, '-H', 'Content-Type: ' + ct,
                            'http://127.0.0.1:%d/c%d.php' % (port, i)], capture_output=True).stdout.decode('latin1')
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', REQUEST_METHOD='POST', GATEWAY_INTERFACE='CGI/1.1',
                   CONTENT_TYPE=ct, CONTENT_LENGTH=str(len(data)), PHPMINI_UPLOAD_TMP_DIR='/tmp')
        r = subprocess.run([BIN, os.path.join(UP, 'm%d.php' % i)], input=data, capture_output=True, env=env)
        m = r.stdout.decode('latin1'); err = r.stderr.decode('latin1')
        same_out = norm(p) == norm(m)
        pf = sorted(os.listdir(po)); mf = sorted(os.listdir(mo))
        same_files = pf == mf and all(open(os.path.join(po, x), 'rb').read() == open(os.path.join(mo, x), 'rb').read() for x in pf)
        san = 'runtime error' in err or 'AddressSanitizer' in err
        if same_out and same_files and not san:
            match += 1; print('  MATCH  %-22s (%d moved files identical)' % (name, len(pf)))
        else:
            differ += 1
            print('  DIFF   %-22s out=%s files=%s sanitizer=%s' % (name, same_out, same_files, san))
            if not same_out:
                import difflib
                for l in list(difflib.unified_diff(norm(p).splitlines(), norm(m).splitlines(), 'php', 'mini', lineterm='', n=1))[:14]: print('         ' + l)
            if not same_files: print('         php files', pf, ' mini files', mf)
            if san: print('         ' + err[:300])
finally:
    srv.terminate(); srv.wait()
    shutil.rmtree(UP, ignore_errors=True)
print('  -- %d match, %d differ' % (match, differ))
sys.exit(1 if differ else 0)
