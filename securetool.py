#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SecureTool - Gelişmiş Kod Analizi & Şifreleme Aracı
Kali Linux için geliştirilmiştir.
"""

import os
import sys
import re
import json
import base64
import hashlib
import getpass
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# RENK & ÇIKTI
# ─────────────────────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def banner():
    print(f"""
{C.RED}{C.BOLD}
 ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ███████╗████████╗ ██████╗  ██████╗ ██╗
██╔════╝ ██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗██║
███████╗ █████╗  ██║     ██║   ██║██████╔╝█████╗     ██║   ██║   ██║██║   ██║██║
╚════██║ ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝     ██║   ██║   ██║██║   ██║██║
███████║ ███████╗╚██████╗╚██████╔╝██║  ██║███████╗   ██║   ╚██████╔╝╚██████╔╝███████╗
╚══════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{C.RESET}
{C.CYAN}        Gelişmiş Kod Analizi & Şifreleme Aracı  |  Kali Linux Edition{C.RESET}
{C.DIM}        v2.0  —  Yalnızca yetkili sistemlerde kullanın{C.RESET}
""")

def menu():
    print(f"""
{C.BOLD}{C.WHITE}╔══════════════════════════════════════════════╗
║           ANA MENÜ                          ║
╠══════════════════════════════════════════════╣
║  {C.RED}[1]{C.WHITE}  Kod Güvenlik Analizi                    ║
║  {C.CYAN}[2]{C.WHITE}  Dosya Şifreleme / Çözme                ║
║  {C.DIM}[0]{C.WHITE}  Çıkış                                   ║
╚══════════════════════════════════════════════╝{C.RESET}
""")

# ─────────────────────────────────────────────────────────────────────────────
# 1. KOD GÜVENLİK ANALİZİ
# ─────────────────────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = ("CRITICAL", C.RED)
    HIGH     = ("HIGH",     C.MAGENTA)
    MEDIUM   = ("MEDIUM",   C.YELLOW)
    LOW      = ("LOW",      C.CYAN)
    INFO     = ("INFO",     C.GREEN)

@dataclass
class Finding:
    severity: Severity
    category: str
    description: str
    line_no: int
    line_content: str
    recommendation: str
    extracted: Optional[str] = None  # credential, token, vb.

@dataclass
class AnalysisResult:
    filepath: str
    language: str
    total_lines: int
    findings: List[Finding] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)

# ── Kural sözlüğü ────────────────────────────────────────────────────────────

RULES = [
    # ── SQL Injection ──────────────────────────────────────────────────────
    {
        "id": "SQL-001",
        "pattern": r'(?i)(execute|exec|query|cursor\.execute)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?["\']?\s*[+%]',
        "severity": Severity.CRITICAL,
        "category": "SQL Injection",
        "description": "Ham kullanıcı girdisi doğrudan SQL sorgusuna ekleniyor (string concat/format).",
        "recommendation": "Parametrik sorgular veya ORM kullanın. Asla f-string/% ile SQL birleştirmeyin.",
    },
    {
        "id": "SQL-002",
        "pattern": r'(?i)f["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?{',
        "severity": Severity.CRITICAL,
        "category": "SQL Injection (f-string)",
        "description": "f-string ile SQL sorgusu oluşturuluyor.",
        "recommendation": "Parametrik sorgular kullanın.",
    },
    # ── XSS ───────────────────────────────────────────────────────────────
    {
        "id": "XSS-001",
        "pattern": r'(?i)innerHTML\s*=\s*(?![\'"]\s*[\'"])',
        "severity": Severity.HIGH,
        "category": "XSS (DOM)",
        "description": "innerHTML'e kullanıcı girdisi yazılıyor.",
        "recommendation": "textContent veya DOMPurify.sanitize() kullanın.",
    },
    {
        "id": "XSS-002",
        "pattern": r'(?i)document\.write\s*\(',
        "severity": Severity.HIGH,
        "category": "XSS (document.write)",
        "description": "document.write kullanımı.",
        "recommendation": "DOM manipülasyonu için createElement kullanın.",
    },
    {
        "id": "XSS-003",
        "pattern": r'(?i)(render_template_string|Markup)\s*\(',
        "severity": Severity.HIGH,
        "category": "XSS / SSTI (Flask)",
        "description": "render_template_string ya da Markup() ile kullanıcı girdisi render ediliyor — Server Side Template Injection riski.",
        "recommendation": "render_template() kullanın, kullanıcı girdisini şablona doğrudan geçirmeyin.",
    },
    # ── Command Injection ─────────────────────────────────────────────────
    {
        "id": "CMD-001",
        "pattern": r'(?i)(os\.system|subprocess\.(call|run|Popen))\s*\(.*?[\+%f]',
        "severity": Severity.CRITICAL,
        "category": "Command Injection",
        "description": "Kullanıcı girdisi doğrudan shell komutuna ekleniyor.",
        "recommendation": "subprocess'i shell=False ile çağırın, argümanları liste olarak geçirin.",
    },
    {
        "id": "CMD-002",
        "pattern": r'(?i)shell\s*=\s*True',
        "severity": Severity.HIGH,
        "category": "Command Injection (shell=True)",
        "description": "shell=True kullanımı komut enjeksiyonuna açık.",
        "recommendation": "Mümkünse shell=False kullanın.",
    },
    # ── Path Traversal ────────────────────────────────────────────────────
    {
        "id": "PATH-001",
        "pattern": r'(?i)open\s*\(\s*(?:request\.|input\(|argv)',
        "severity": Severity.HIGH,
        "category": "Path Traversal",
        "description": "Kullanıcı kontrolündeki değer doğrudan dosya yolu olarak kullanılıyor.",
        "recommendation": "os.path.abspath + os.path.commonpath ile yolu doğrulayın.",
    },
    # ── SSRF ──────────────────────────────────────────────────────────────
    {
        "id": "SSRF-001",
        "pattern": r'(?i)(requests\.(get|post)|urllib\.request\.urlopen)\s*\(.*?(request\.|input\(|argv)',
        "severity": Severity.HIGH,
        "category": "SSRF",
        "description": "Kullanıcı girdisi HTTP isteğinin URL'i olarak kullanılıyor.",
        "recommendation": "İzin verilen host listesi (allowlist) oluşturun.",
    },
    # ── IDOR ──────────────────────────────────────────────────────────────
    {
        "id": "IDOR-001",
        "pattern": r'(?i)(WHERE\s+id\s*=\s*["\']?\s*\{\s*|WHERE\s+user_id\s*=\s*["\']?\s*\{)',
        "severity": Severity.HIGH,
        "category": "IDOR",
        "description": "Yetkilendirme kontrolü yapılmadan ID tabanlı sorgu.",
        "recommendation": "Kimlik doğrulama sonrası oturum kullanıcısıyla ID'yi doğrulayın.",
    },
    # ── Zayıf Şifreleme ───────────────────────────────────────────────────
    {
        "id": "CRYPTO-001",
        "pattern": r'(?i)(hashlib\.(md5|sha1)\s*\(|MD5|SHA1)\b',
        "severity": Severity.HIGH,
        "category": "Zayıf Hash (MD5/SHA1)",
        "description": "MD5 veya SHA-1 kullanımı — kriptografik olarak kırılmış.",
        "recommendation": "SHA-256/512 ya da Argon2/bcrypt kullanın.",
    },
    {
        "id": "CRYPTO-002",
        "pattern": r'(?i)(DES|RC4|Blowfish|ECB)\b',
        "severity": Severity.HIGH,
        "category": "Zayıf Şifreleme Algoritması",
        "description": "Güvensiz şifreleme algoritması tespit edildi.",
        "recommendation": "AES-256-GCM kullanın.",
    },
    {
        "id": "CRYPTO-003",
        "pattern": r'(?i)random\.(random|randint|choice)\b',
        "severity": Severity.MEDIUM,
        "category": "Kriptografik Olmayan Rastgelelik",
        "description": "random modülü şifreleme/token üretimi için uygun değil.",
        "recommendation": "secrets modülünü veya os.urandom() kullanın.",
    },
    # ── Güvensiz Deserialize ──────────────────────────────────────────────
    {
        "id": "DESER-001",
        "pattern": r'(?i)(pickle\.loads?|yaml\.load\s*\((?!.*Loader))',
        "severity": Severity.CRITICAL,
        "category": "Güvensiz Deserializasyon",
        "description": "pickle.load veya yaml.load (güvensiz) kullanımı — RCE riski.",
        "recommendation": "yaml.safe_load kullanın, pickle'ı güvenilmeyen veriye uygulamayın.",
    },
    # ── Debug / Verbose Error ─────────────────────────────────────────────
    {
        "id": "DEBUG-001",
        "pattern": r'(?i)(app\.run\s*\(.*debug\s*=\s*True|DEBUG\s*=\s*True)',
        "severity": Severity.MEDIUM,
        "category": "Debug Modu Açık",
        "description": "Üretim ortamında debug=True kullanımı.",
        "recommendation": "DEBUG=False olarak ayarlayın, ortam değişkeni kullanın.",
    },
    # ── eval / exec ───────────────────────────────────────────────────────
    {
        "id": "CODE-001",
        "pattern": r'(?i)\b(eval|exec)\s*\(\s*(?![\'"]\s)',
        "severity": Severity.CRITICAL,
        "category": "Kod Çalıştırma (eval/exec)",
        "description": "eval/exec ile dinamik kod çalıştırma — RCE riski.",
        "recommendation": "eval/exec kullanmayın; ast.literal_eval veya yapısal çözümleme yapın.",
    },
    # ── Hardcoded Credentials ─────────────────────────────────────────────
    {
        "id": "CRED-001",
        "pattern": r'(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*=\s*["\'][^"\']{4,}["\']',
        "severity": Severity.CRITICAL,
        "category": "Hardcoded Kimlik Bilgisi",
        "description": "Kaynak kodda sabit şifre/anahtar/token.",
        "recommendation": "Ortam değişkenleri veya vault kullanın.",
    },
    {
        "id": "CRED-002",
        "pattern": r'(?i)(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z\-]+)',
        "severity": Severity.CRITICAL,
        "category": "Sızdırılmış API Anahtarı",
        "description": "AWS, Google, GitHub veya Slack API anahtarı tespit edildi.",
        "recommendation": "Anahtarı hemen iptal edin ve secret manager kullanın.",
    },
    # ── JWT ───────────────────────────────────────────────────────────────
    {
        "id": "JWT-001",
        "pattern": r'(?i)algorithm\s*=\s*["\']none["\']',
        "severity": Severity.CRITICAL,
        "category": "JWT Algorithm None",
        "description": "JWT'de algorithm='none' imzayı devre dışı bırakır.",
        "recommendation": "RS256 veya ES256 kullanın.",
    },
    # ── Open Redirect ─────────────────────────────────────────────────────
    {
        "id": "REDIR-001",
        "pattern": r'(?i)(redirect|header\s*\(\s*["\']Location:)\s*.*?(request\.|input\(|\$_GET|\$_POST)',
        "severity": Severity.MEDIUM,
        "category": "Open Redirect",
        "description": "Kullanıcı girdisi yönlendirme URL'i olarak kullanılıyor.",
        "recommendation": "URL'yi izin verilen domain listesiyle doğrulayın.",
    },
]

# ── Credential çıkarma pattern'leri ──────────────────────────────────────────

CREDENTIAL_PATTERNS = [
    ("username", r'(?i)(username|user|login|kullanici)\s*[=:]\s*["\']([^"\']{2,})["\']'),
    ("password", r'(?i)(password|passwd|pwd|parola|sifre)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    ("api_key",  r'(?i)(api_key|apikey|api-key|key)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("token",    r'(?i)(token|access_token|auth_token|bearer)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("secret",   r'(?i)(secret|client_secret|app_secret)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    ("db_url",   r'(?i)(DATABASE_URL|DB_URL|CONNECTION_STRING)\s*[=:]\s*["\']([^"\']+)["\']'),
    ("private_key", r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
]

def detect_language(filepath: str, content: str) -> str:
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".php": "PHP", ".java": "Java", ".go": "Go", ".rb": "Ruby",
        ".cs": "C#", ".cpp": "C++", ".c": "C", ".sh": "Bash",
        ".rs": "Rust", ".kt": "Kotlin",
    }
    ext = Path(filepath).suffix.lower()
    return ext_map.get(ext, "Bilinmeyen")

def analyze_file(filepath: str) -> AnalysisResult:
    path = Path(filepath)
    if not path.exists():
        print(f"{C.RED}[!] Dosya bulunamadı: {filepath}{C.RESET}")
        sys.exit(1)

    content = path.read_text(errors="replace")
    lines = content.splitlines()
    language = detect_language(filepath, content)

    result = AnalysisResult(
        filepath=filepath,
        language=language,
        total_lines=len(lines),
    )

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for rule in RULES:
            if re.search(rule["pattern"], line):
                finding = Finding(
                    severity=rule["severity"],
                    category=rule["category"],
                    description=rule["description"],
                    line_no=line_no,
                    line_content=line.strip()[:120],
                    recommendation=rule["recommendation"],
                )
                result.findings.append(finding)

        for cred_type, pattern in CREDENTIAL_PATTERNS:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                value = m.group(2) if len(m.groups()) >= 2 else m.group(0)
                # Sadece anlamlı değerler
                if value and len(value) > 3 and value.lower() not in (
                    "changeme", "your_password", "xxx", "placeholder", "example"
                ):
                    result.credentials.append({
                        "type": cred_type,
                        "value": value,
                        "line": line_no,
                        "raw": line.strip()[:120],
                    })

    # Duplicate finding temizle (aynı satır, aynı kategori)
    seen = set()
    unique = []
    for f in result.findings:
        key = (f.line_no, f.category)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    result.findings = unique

    return result

def print_analysis(result: AnalysisResult):
    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    sev_counts = {s: 0 for s in sev_order}
    for f in result.findings:
        sev_counts[f.severity] += 1

    print(f"\n{C.BOLD}{C.WHITE}═══════════════════════════════════════════════════{C.RESET}")
    print(f"  {C.BOLD}Dosya   :{C.RESET} {result.filepath}")
    print(f"  {C.BOLD}Dil     :{C.RESET} {result.language}")
    print(f"  {C.BOLD}Satır   :{C.RESET} {result.total_lines}")
    print(f"  {C.BOLD}Bulgular:{C.RESET} {len(result.findings)} güvenlik açığı")
    print(f"{C.BOLD}{C.WHITE}═══════════════════════════════════════════════════{C.RESET}\n")

    # Özet sayaç
    for sev in sev_order:
        count = sev_counts[sev]
        if count:
            label, color = sev.value
            bar = "█" * min(count, 30)
            print(f"  {color}{label:<10}{C.RESET}  {bar} {count}")
    print()

    # Bulgular (önem sırasına göre)
    for sev in sev_order:
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        label, color = sev.value
        print(f"{color}{C.BOLD}── {label} ({'─' * (40 - len(label))}){C.RESET}")
        for f in group:
            print(f"\n  {C.BOLD}[!] {f.category}{C.RESET}")
            print(f"  {C.DIM}Satır {f.line_no}:{C.RESET} {f.description}")
            print(f"  {C.DIM}Kod  :{C.RESET} {C.YELLOW}{f.line_content}{C.RESET}")
            print(f"  {C.GREEN}[+] Öneri:{C.RESET} {f.recommendation}")
        print()

    # Credential Raporu
    if result.credentials:
        print(f"\n{C.RED}{C.BOLD}╔══════════════════════════════════════════╗")
        print(f"║   AYIKLANAN KİMLİK BİLGİLERİ ({len(result.credentials)} adet)   ║")
        print(f"╚══════════════════════════════════════════╝{C.RESET}\n")
        for i, cred in enumerate(result.credentials, 1):
            ctype = cred["type"].upper()
            value = cred["value"]
            # Hassas değerleri kısmen maskele (son 4 karakter görünür)
            if len(value) > 8:
                masked = "*" * (len(value) - 4) + value[-4:]
            else:
                masked = "*" * len(value)
            print(f"  {C.CYAN}[{i}]{C.RESET} {C.BOLD}{ctype:<15}{C.RESET} | Satır {cred['line']:<5} | {C.YELLOW}{masked}{C.RESET}")
            print(f"       {C.DIM}{cred['raw']}{C.RESET}\n")

    # JSON kaydet
    out = {
        "file": result.filepath,
        "language": result.language,
        "total_lines": result.total_lines,
        "findings": [
            {
                "severity": f.severity.value[0],
                "category": f.category,
                "line": f.line_no,
                "description": f.description,
                "code": f.line_content,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
        "credentials": result.credentials,
    }
    report_path = Path(result.filepath).stem + "_securetool_report.json"
    Path(report_path).write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n{C.GREEN}[+] Rapor kaydedildi:{C.RESET} {report_path}\n")

# ─────────────────────────────────────────────────────────────────────────────
# 2. ŞİFRELEME / ÇÖZME (AES-256-GCM + Argon2id)
# ─────────────────────────────────────────────────────────────────────────────

MAGIC = b"STOOL\x02"          # dosya başlığı
SALT_LEN  = 32
NONCE_LEN = 12
ITER_LAYERS = 3               # katmanlı şifreleme sayısı

def derive_key(password: str, salt: bytes) -> bytes:
    """Argon2id ile anahtar türetme — kaba kuvvete çok dayanıklı."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography kütüphanesi yüklü değil: pip install cryptography")
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=4,
        lanes=4,
        memory_cost=65536,  # 64 MB RAM
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Katmanlı AES-256-GCM şifreleme:
      - Her katman için ayrı tuz + nonce
      - ITER_LAYERS kez şifreleme
      - Son çıktı base85 encode (ascii güvenli)
    """
    salt = os.urandom(SALT_LEN)
    payload = data
    layer_meta = []

    for layer in range(ITER_LAYERS):
        nonce = os.urandom(NONCE_LEN)
        layer_salt = hashlib.sha256(salt + layer.to_bytes(4, "big")).digest()
        key = derive_key(password + f":layer:{layer}", layer_salt)
        aesgcm = AESGCM(key)
        payload = aesgcm.encrypt(nonce, payload, layer_salt)
        layer_meta.append(nonce)

    # Başlık: MAGIC | salt | nonce0 | nonce1 | nonce2 | payload
    header = MAGIC + salt
    for n in layer_meta:
        header += n
    raw = header + payload

    # Ekstra obfuscation: base85 + XOR ile basit stream cipher
    b85 = base64.b85encode(raw)
    xor_key = hashlib.sha512(password.encode() + salt).digest()
    xored = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(b85))
    return base64.b64encode(xored)

def decrypt_data(enc_data: bytes, password: str) -> bytes:
    """Şifre çözme — katmanları ters sırada açar."""
    try:
        b64_decoded = base64.b64decode(enc_data)
    except Exception:
        raise ValueError("Geçersiz şifreli veri formatı.")

    # Geçici salt almanın tek yolu: başlığı XOR'suz okumaya çalışmak — deneme yap
    # İlk 32 bayt XOR anahtarının türetilmesinde kullanılıyor; önce kaba decode dene
    # NOT: XOR'u geri almak için önce doğru password lazım
    # Bu nedenle şifre çözme işlemi sadece doğru parola ile mümkün.

    # Deneme: b64_decoded'u çeşitli xor_key uzunluklarıyla decode et
    # Gerçek salt: base85 decode sonrası MAGIC+salt kısmında
    # → Brute force engellemek için salt olmadan xor_key üretemeyiz.
    # → Çözüm: raw'ın ilk SALT_LEN+len(MAGIC) baytını bulmak için şifreyi kullan.

    # Adım 1: xor_key için "tahmin" salt — tüm olası salt için tek yol: gerçek decode
    # Biz burada MAGIC baytlarını kullanarak doğrulama yapıyoruz.
    found_salt = None
    decoded_b85 = None

    # Makul bir brute force olmadığından, salt bilinen değil.
    # Gerçek uygulama: salt'ı şifreli dosyanın başına XOR'suz (temiz) koyabiliriz.
    # Bunu yapalım — salt ilk SALT_LEN bayt olarak açık saklanır, sadece payload şifreli.

    # Yeniden yapı: [MAGIC(6)] [SALT(32)] [XOR(b85(nonce0+nonce1+nonce2+ciphertext))]
    # Bu sayede decrypt sırasında salt'ı açık okuyabiliriz.
    raise ValueError(
        "Bu fonksiyon doğrudan çağrılmaz. "
        "Lütfen encrypt_file / decrypt_file kullanın."
    )

def encrypt_file(filepath: str, password: str):
    path = Path(filepath)
    data = path.read_bytes()
    print(f"\n{C.CYAN}[*] Şifreleniyor...{C.RESET}")
    print(f"    Boyut      : {len(data):,} bayt")
    print(f"    Katman     : {ITER_LAYERS}x AES-256-GCM")
    print(f"    KDF        : Argon2id (64MB RAM, 4 iterasyon)")

    salt = os.urandom(SALT_LEN)
    payload = data
    nonces = []

    for layer in range(ITER_LAYERS):
        nonce = os.urandom(NONCE_LEN)
        layer_salt = hashlib.sha256(salt + layer.to_bytes(4, "big")).digest()
        key = derive_key(password + f":layer:{layer}", layer_salt)
        aesgcm = AESGCM(key)
        payload = aesgcm.encrypt(nonce, payload, layer_salt)
        nonces.append(nonce)
        print(f"    Katman {layer+1}   : {C.GREEN}OK{C.RESET}")

    # XOR stream
    xor_key = hashlib.sha512(password.encode() + salt).digest()

    # Yapı: MAGIC | SALT | NONCE0..2 | XOR(ciphertext)
    header = MAGIC + salt
    for n in nonces:
        header += n

    xored_payload = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(payload))

    out_path = path.with_suffix(path.suffix + ".stenc")
    out_path.write_bytes(header + xored_payload)
    print(f"\n{C.GREEN}[+] Şifreli dosya:{C.RESET} {out_path}")
    print(f"    Çıktı boyutu: {out_path.stat().st_size:,} bayt")

def decrypt_file(filepath: str, password: str):
    path = Path(filepath)
    raw = path.read_bytes()

    # Başlık doğrulama
    if not raw.startswith(MAGIC):
        print(f"{C.RED}[!] Geçersiz dosya ya da yanlış format.{C.RESET}")
        sys.exit(1)

    offset = len(MAGIC)
    salt   = raw[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonces = []
    for _ in range(ITER_LAYERS):
        nonces.append(raw[offset:offset + NONCE_LEN])
        offset += NONCE_LEN

    xored_payload = raw[offset:]
    xor_key = hashlib.sha512(password.encode() + salt).digest()
    payload = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(xored_payload))

    print(f"\n{C.CYAN}[*] Çözülüyor...{C.RESET}")
    for layer in range(ITER_LAYERS - 1, -1, -1):
        nonce = nonces[layer]
        layer_salt = hashlib.sha256(salt + layer.to_bytes(4, "big")).digest()
        key = derive_key(password + f":layer:{layer}", layer_salt)
        aesgcm = AESGCM(key)
        try:
            payload = aesgcm.decrypt(nonce, payload, layer_salt)
            print(f"    Katman {layer+1}   : {C.GREEN}OK{C.RESET}")
        except Exception:
            print(f"\n{C.RED}[!] Şifre çözme başarısız — yanlış parola ya da bozuk dosya.{C.RESET}")
            sys.exit(1)

    if filepath.endswith(".stenc"):
        out_path = Path(filepath[:-6])
    else:
        out_path = Path(filepath + ".dec")

    out_path.write_bytes(payload)
    print(f"\n{C.GREEN}[+] Çözülen dosya:{C.RESET} {out_path}")
    print(f"    Boyut: {len(payload):,} bayt")

# ─────────────────────────────────────────────────────────────────────────────
# ANA DÖNGÜ
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis_mode():
    print(f"\n{C.CYAN}[>] Analiz edilecek dosya yolunu girin:{C.RESET} ", end="")
    filepath = input().strip()
    if not filepath:
        return
    result = analyze_file(filepath)
    print_analysis(result)

def run_encryption_mode():
    print(f"""
{C.BOLD}{C.WHITE}  Şifreleme Seçenekleri:
  {C.CYAN}[e]{C.WHITE} Şifrele
  {C.CYAN}[d]{C.WHITE} Çöz{C.RESET}
""")
    choice = input("  Seçim: ").strip().lower()
    if choice not in ("e", "d"):
        print(f"{C.RED}[!] Geçersiz seçim.{C.RESET}")
        return

    print(f"\n{C.CYAN}[>] Dosya yolu:{C.RESET} ", end="")
    filepath = input().strip()
    if not filepath:
        return

    password = getpass.getpass(f"{C.CYAN}[>] Parola:{C.RESET} ")
    if not password:
        print(f"{C.RED}[!] Parola boş olamaz.{C.RESET}")
        return

    if choice == "e":
        if len(password) < 12:
            print(f"{C.YELLOW}[!] Uyarı: Parola çok kısa (<12 karakter). Daha güçlü bir parola öneririz.{C.RESET}")
        confirm = getpass.getpass(f"{C.CYAN}[>] Parolayı tekrar girin:{C.RESET} ")
        if password != confirm:
            print(f"{C.RED}[!] Parolalar eşleşmiyor.{C.RESET}")
            return
        encrypt_file(filepath, password)
    else:
        decrypt_file(filepath, password)

def main():
    if not CRYPTO_AVAILABLE:
        print(f"{C.YELLOW}[!] cryptography modülü eksik. Şifreleme modülü devre dışı.{C.RESET}")
        print(f"    Yüklemek için: {C.CYAN}pip install cryptography{C.RESET}\n")

    banner()

    while True:
        menu()
        try:
            choice = input(f"  {C.BOLD}Seçim:{C.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.DIM}Çıkılıyor...{C.RESET}\n")
            sys.exit(0)

        if choice == "1":
            run_analysis_mode()
        elif choice == "2":
            if not CRYPTO_AVAILABLE:
                print(f"{C.RED}[!] Şifreleme için cryptography modülü gerekli.{C.RESET}")
                print(f"    pip install cryptography")
            else:
                run_encryption_mode()
        elif choice == "0":
            print(f"\n{C.DIM}Çıkılıyor...{C.RESET}\n")
            sys.exit(0)
        else:
            print(f"{C.YELLOW}[!] Geçersiz seçim.{C.RESET}")

if __name__ == "__main__":
    main()
