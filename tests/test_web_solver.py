"""
web_solver 单元/集成测试:
 - 分类器对合成题目的判定
 - 各策略 payload 生成
 - 端到端动态求解(用 python http.server 模拟易受攻击目标)
"""
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'phpserialize-solver'))

from web_solver import WebClassifier, WebSolver
from web_solver.strategies import strategies_for, _read_sources
from web_solver.solver import extract_flag


def _write(tmp, name, content):
    p = Path(tmp) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    return p


# ---------- 分类器 ----------

def test_classify_php_unserialize():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'index.php', '''<?php
class A { public $x; function __destruct(){ eval($this->x); } }
unserialize($_GET['data']);
?>''')
        cls = WebClassifier().classify(tmp)
        assert cls.stack == 'php'
        vtypes = [v for v, _ in cls.top_vulns]
        assert 'unserialize' in vtypes, f'unserialize not in {vtypes}'
        assert cls.primary_vuln[1] >= 70


def test_classify_sqli():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'index.php', '''<?php
$conn = mysqli_connect("db","root","root","ctf");
$id = $_GET['id'];
$r = mysqli_query($conn, "SELECT * FROM users WHERE id=$id");
?>''')
        cls = WebClassifier().classify(tmp)
        vtypes = [v for v, _ in cls.top_vulns]
        assert 'sqli' in vtypes


def test_classify_flask_ssti():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'app.py', '''from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route("/")
def index():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hi " + name + "</h1>")
''')
        cls = WebClassifier().classify(tmp)
        assert cls.stack == 'python'
        assert cls.framework == 'flask'
        vtypes = [v for v, _ in cls.top_vulns]
        assert 'ssti' in vtypes


def test_classify_docker_detection():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'docker-compose.yml', 'version: "3"\nservices:\n  web:\n    image: php\n')
        _write(tmp, 'src/index.php', '<?php phpinfo();')
        cls = WebClassifier().classify(tmp)
        assert cls.has_docker
        assert cls.docker_compose.endswith('docker-compose.yml')


# ---------- flag 提取 ----------

def test_extract_flag_formats():
    assert extract_flag('well done flag{abc_123} !') == 'flag{abc_123}'
    assert extract_flag('NSSCTF{x9z}') == 'NSSCTF{x9z}'
    assert extract_flag('no flag here') is None


# ---------- 策略 ----------

def test_strategies_selected_for_unserialize():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'index.php', '''<?php
class B { function __wakeup(){ system("id"); } }
unserialize($_COOKIE['token']);
?>''')
        cls = WebClassifier().classify(tmp)
        strats = strategies_for(cls)
        types = [s.vuln_type for s in strats]
        assert 'unserialize' in types
        # unserialize 应排最前(置信度最高)
        assert strats[0].vuln_type == 'unserialize'


def test_unserialize_payloads_generated():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'index.php', '''<?php
class FLAG { public $flag_command = "system('cat /flag');";
    function __destruct(){ eval($this->flag_command); } }
unserialize($_POST['data']);
?>''')
        cls = WebClassifier().classify(tmp)
        sources = _read_sources(cls)
        strats = strategies_for(cls)
        unser = [s for s in strats if s.vuln_type == 'unserialize'][0]
        attempts = unser.payloads(cls, sources)
        assert attempts, '应生成反序列化 payload'
        # 至少一个 payload 的 data/params 非空
        assert any(a.data or a.params for a in attempts)


# ---------- 端到端动态求解 (内建 mock 靶机) ----------

def _start_mock_sqli_server(port):
    """一个模拟 SQL 注入登录绕过的迷你 HTTP 服务。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    FLAG = 'flag{mock_sqli_bypass_ok}'

    class H(BaseHTTPRequestHandler):
        def _reply(self, body):
            data = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
            user = q.get('username', [''])[0]
            if "'" in user and ('OR' in user.upper() or 'or' in user):
                self._reply(f'Login success! {FLAG}')
            else:
                self._reply('Login failed')

        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode()
            if "'" in body and ('OR' in body.upper() or 'or' in body.lower()):
                self._reply(f'Login success! {FLAG}')
            else:
                self._reply('Login failed')

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(('127.0.0.1', port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_end_to_end_sqli_mock():
    """起一个模拟 SQLi 靶机, solver 应自动绕过登录拿到 flag。"""
    srv = _start_mock_sqli_server(0)
    port = srv.server_address[1]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, 'index.php', '''<?php
$u = $_GET['username'];
$r = mysqli_query($db, "SELECT * FROM users WHERE name='$u'");
?>''')
            solver = WebSolver(timeout=5, verbose=False, max_attempts=40)
            r = solver.solve(tmp, target_url=f'http://127.0.0.1:{port}/')
            assert r.success, f'应解出 mock SQLi: {r.error}'
            assert r.flag == 'flag{mock_sqli_bypass_ok}'
            assert r.primary_vuln == 'sqli'
    finally:
        srv.shutdown()


def test_analyze_only_no_network():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, 'app.py', '''import pickle, base64
from flask import request
data = base64.b64decode(request.cookies.get("d"))
pickle.loads(data)
''')
        solver = WebSolver()
        r = solver.analyze(tmp)
        assert r.stack == 'python'
        assert 'deserialization' in [v for v, _ in r.top_vulns], r.top_vulns
        assert not r.success  # analyze 不打 payload


if __name__ == '__main__':
    # 允许无 pytest 直接跑
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            print(f'  ✓ {fn.__name__}')
            passed += 1
        except Exception as e:
            print(f'  ✗ {fn.__name__}: {e}')
            failed += 1
    print(f'\n{passed}/{passed+failed} 通过')
    sys.exit(1 if failed else 0)
