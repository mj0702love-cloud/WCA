from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import uuid
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
from PIL import Image


ROOT = Path(__file__).resolve().parent
STORAGE_DIR = Path(os.getenv("WCA_STORAGE_DIR", str(ROOT))).resolve()
DATA_DIR = STORAGE_DIR / "data"
UPLOAD_DIR = STORAGE_DIR / "uploads"
STATIC_DIR = ROOT / "static"
DB_PATH = STORAGE_DIR / "closet.sqlite3"
SESSION_DAYS = 30
DEFAULT_WEATHER = {
    "location": "대한민국 서울 강서구",
    "lat": 37.5509,
    "lon": 126.8495,
}
REGION_OPTIONS = {
    "서울 강남구": (37.5172, 127.0473),
    "서울 강동구": (37.5301, 127.1238),
    "서울 강북구": (37.6396, 127.0257),
    "서울 강서구": (37.5509, 126.8495),
    "서울 관악구": (37.4784, 126.9516),
    "서울 광진구": (37.5385, 127.0823),
    "서울 구로구": (37.4955, 126.8877),
    "서울 금천구": (37.4569, 126.8955),
    "서울 노원구": (37.6542, 127.0568),
    "서울 도봉구": (37.6688, 127.0471),
    "서울 동대문구": (37.5744, 127.0396),
    "서울 동작구": (37.5124, 126.9393),
    "서울 마포구": (37.5663, 126.9019),
    "서울 서대문구": (37.5791, 126.9368),
    "서울 서초구": (37.4836, 127.0327),
    "서울 성동구": (37.5633, 127.0369),
    "서울 성북구": (37.5894, 127.0167),
    "서울 송파구": (37.5145, 127.1059),
    "서울 양천구": (37.5169, 126.8665),
    "서울 영등포구": (37.5264, 126.8962),
    "서울 용산구": (37.5326, 126.9905),
    "서울 은평구": (37.6027, 126.9291),
    "서울 종로구": (37.5735, 126.9788),
    "서울 중구": (37.5636, 126.9976),
    "서울 중랑구": (37.6063, 127.0925),
    "부산 해운대구": (35.1631, 129.1635),
    "부산 강서구": (35.2122, 128.9800),
    "부산 부산진구": (35.1629, 129.0532),
    "부산 수영구": (35.1456, 129.1132),
    "부산 남구": (35.1366, 129.0844),
    "부산 동래구": (35.2048, 129.0838),
    "부산 사하구": (35.1046, 128.9748),
    "인천 연수구": (37.4102, 126.6783),
    "인천 남동구": (37.4473, 126.7315),
    "인천 부평구": (37.5070, 126.7218),
    "대구 수성구": (35.8582, 128.6306),
    "대구 중구": (35.8695, 128.6062),
    "대전 서구": (36.3554, 127.3838),
    "대전 유성구": (36.3622, 127.3562),
    "광주 서구": (35.1520, 126.8903),
    "광주 북구": (35.1741, 126.9110),
    "울산 남구": (35.5438, 129.3301),
    "세종시": (36.4800, 127.2890),
    "경기 수원시": (37.2636, 127.0286),
    "경기 성남시": (37.4200, 127.1265),
    "경기 고양시": (37.6584, 126.8320),
    "경기 용인시": (37.2411, 127.1776),
    "경기 부천시": (37.5034, 126.7660),
    "경기 김포시": (37.6154, 126.7156),
    "강원 춘천시": (37.8813, 127.7298),
    "충북 청주시": (36.6424, 127.4890),
    "충남 천안시": (36.8151, 127.1139),
    "전북 전주시": (35.8242, 127.1480),
    "전남 여수시": (34.7604, 127.6622),
    "경북 포항시": (36.0190, 129.3435),
    "경남 창원시": (35.2285, 128.6811),
    "제주 제주시": (33.4996, 126.5312),
    "제주 서귀포시": (33.2541, 126.5601),
}
REGION_RANK = {name: index for index, name in enumerate(REGION_OPTIONS)}

DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)


def external_get(url: str, **kwargs: Any) -> requests.Response:
    session = requests.Session()
    session.trust_env = False
    return session.get(url, **kwargs)


def external_post(url: str, **kwargs: Any) -> requests.Response:
    session = requests.Session()
    session.trust_env = False
    return session.post(url, **kwargs)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = MEMORY")
    return conn


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS Users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                weather_location TEXT,
                weather_lat REAL,
                weather_lon REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS Sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS PasswordResetCodes (
                reset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS Clothes (
                cloth_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                image_path TEXT,
                category TEXT NOT NULL,
                sub_category TEXT,
                color TEXT,
                material TEXT,
                warmth TEXT,
                status TEXT DEFAULT '착용가능',
                notes TEXT,
                user_override INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS WearHistory (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                wear_date DATE NOT NULL,
                cloth_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cloth_id) REFERENCES Clothes(cloth_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS TrendingLooks (
                trend_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_site TEXT,
                style_tag TEXT,
                color_combination TEXT,
                recommended_temp INTEGER,
                scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        user_columns = table_columns(conn, "Users")
        if "email" not in user_columns:
            conn.execute("ALTER TABLE Users ADD COLUMN email TEXT")
        if "weather_location" not in user_columns:
            conn.execute("ALTER TABLE Users ADD COLUMN weather_location TEXT")
        if "weather_lat" not in user_columns:
            conn.execute("ALTER TABLE Users ADD COLUMN weather_lat REAL")
        if "weather_lon" not in user_columns:
            conn.execute("ALTER TABLE Users ADD COLUMN weather_lon REAL")
        if "user_id" not in table_columns(conn, "Clothes"):
            conn.execute("ALTER TABLE Clothes ADD COLUMN user_id INTEGER")
        if "user_override" not in table_columns(conn, "Clothes"):
            conn.execute("ALTER TABLE Clothes ADD COLUMN user_override INTEGER DEFAULT 0")
        count = conn.execute("SELECT COUNT(*) FROM TrendingLooks").fetchone()[0]
        if count == 0:
            conn.executemany(
                """
                INSERT INTO TrendingLooks
                (source_site, style_tag, color_combination, recommended_temp)
                VALUES (?, ?, ?, ?)
                """,
                [
                    ("sample", "미니멀", "블랙+화이트", 18),
                    ("sample", "캐주얼", "네이비+그레이", 15),
                    ("sample", "스트릿", "차콜+블랙", 10),
                    ("sample", "프레피", "베이지+브라운", 20),
                    ("sample", "시티보이", "카키+아이보리", 16),
                ],
            )


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def cookie_value(handler: SimpleHTTPRequestHandler, name: str) -> str | None:
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        if "=" not in part:
            continue
        key, value = part.strip().split("=", 1)
        if key == name:
            return value
    return None


def current_user(handler: SimpleHTTPRequestHandler) -> dict[str, Any] | None:
    token = cookie_value(handler, "wearon_session")
    if not token:
        return None
    now = datetime.now().isoformat(timespec="seconds")
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.user_id, u.username, u.email, u.display_name, u.weather_location, u.weather_lat, u.weather_lon
            FROM Sessions s
            JOIN Users u ON u.user_id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            """,
            (hash_token(token), now),
        ).fetchone()
    return row_to_dict(row) if row else None


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(days=SESSION_DAYS)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO Sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hash_token(token), user_id, expires.isoformat(timespec="seconds")),
        )
    return token


def session_cookie(token: str) -> str:
    max_age = SESSION_DAYS * 24 * 60 * 60
    return f"wearon_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"


def clear_session_cookie() -> str:
    return "wearon_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"


def read_json(handler: SimpleHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))


def write_json(
    handler: SimpleHTTPRequestHandler,
    payload: Any,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    for key, value in (headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def write_text(handler: SimpleHTTPRequestHandler, text: str, status: int = 200, content_type: str = "text/html") -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", f"{content_type}; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def parse_data_url(data_url: str) -> tuple[str, bytes]:
    match = re.match(r"^data:(?P<mime>[\w/+.-]+);base64,(?P<data>.+)$", data_url)
    if not match:
        raise ValueError("이미지 데이터 형식이 올바르지 않습니다.")
    return match.group("mime"), base64.b64decode(match.group("data"))


def remove_background_if_available(image_bytes: bytes) -> tuple[bytes, bool]:
    try:
        from rembg import remove  # type: ignore

        return remove(image_bytes), True
    except Exception:
        return image_bytes, False


def save_image(data_url: str) -> tuple[str, bool]:
    _, image_bytes = parse_data_url(data_url)
    processed, removed_bg = remove_background_if_available(image_bytes)
    image_id = f"{uuid.uuid4().hex}.png"
    target = UPLOAD_DIR / image_id

    try:
        from io import BytesIO

        with Image.open(BytesIO(processed)) as img:
            img = img.convert("RGBA")
            img.thumbnail((1200, 1200))
            img.save(target, "PNG")
    except Exception:
        target.write_bytes(processed)

    return f"/uploads/{image_id}", removed_bg


def image_path_to_data_url(image_path: str | None) -> str | None:
    if not image_path:
        return None
    path = ROOT / image_path.lstrip("/")
    if not path.exists():
        return None
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def analyze_clothing_with_openai(image_path: str | None) -> dict[str, str]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or not image_path:
        return {}

    image_data = image_path_to_data_url(image_path)
    if not image_data:
        return {}

    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "category": {"type": "string"},
            "sub_category": {"type": "string"},
            "color": {"type": "string"},
            "material": {"type": "string"},
            "warmth": {"type": "string"},
            "name": {"type": "string"},
            "notes": {"type": "string"},
        },
        "required": ["category", "sub_category", "color", "material", "warmth", "name", "notes"],
    }
    payload = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4o"),
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "이미지 속 의류 한 벌을 분석해서 한국어 JSON으로만 답하세요. "
                            "category는 상의, 하의, 아우터, 원피스, 신발, 가방, 액세서리 중 하나에 가깝게 쓰세요. "
                            "warmth는 얇음, 보통, 따뜻함, 매우 따뜻함 중 하나로 쓰세요."
                        ),
                    },
                    {"type": "input_image", "image_url": image_data},
                ],
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "clothing_tags",
                "schema": schema,
                "strict": True,
            }
        },
    }

    try:
        response = external_post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        output_text = data.get("output_text")
        if not output_text:
            for item in data.get("output", []):
                for content in item.get("content", []):
                    if content.get("type") in {"output_text", "text"}:
                        output_text = content.get("text")
                        break
        return json.loads(output_text or "{}")
    except Exception as exc:
        return {"notes": f"AI 태깅 실패: {exc}"}


def public_user(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "email": row["email"],
        "display_name": row["display_name"] or row["username"],
        "weather_location": row["weather_location"],
        "weather_lat": row["weather_lat"],
        "weather_lon": row["weather_lon"],
    }


def register_user(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    username = str(payload.get("username") or "").strip().lower()
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")
    display_name = str(payload.get("display_name") or username).strip()
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", username):
        raise ValueError("아이디는 3~32자의 영문, 숫자, 점, 밑줄, 하이픈만 사용할 수 있습니다.")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("올바른 이메일을 입력하세요.")
    if len(password) < 8:
        raise ValueError("비밀번호는 8자 이상이어야 합니다.")

    with get_conn() as conn:
        first_user = conn.execute("SELECT COUNT(*) FROM Users").fetchone()[0] == 0
        duplicate = conn.execute("SELECT 1 FROM Users WHERE username = ?", (username,)).fetchone()
        if duplicate:
            raise ValueError("이미 사용 중인 아이디입니다. 다른 아이디를 입력하세요.")
        duplicate_email = conn.execute("SELECT 1 FROM Users WHERE email = ?", (email,)).fetchone()
        if duplicate_email:
            raise ValueError("이미 사용 중인 이메일입니다. 다른 이메일을 입력하세요.")
        try:
            cursor = conn.execute(
                "INSERT INTO Users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)",
                (username, email, hash_password(password), display_name),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("이미 사용 중인 아이디입니다.") from exc
        user_id = int(cursor.lastrowid)
        if first_user:
            conn.execute("UPDATE Clothes SET user_id = ? WHERE user_id IS NULL", (user_id,))
        row = conn.execute(
            "SELECT user_id, username, email, display_name, weather_location, weather_lat, weather_lon FROM Users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    token = create_session(user_id)
    return public_user(row), token


def login_user(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    username = str(payload.get("username") or "").strip().lower()
    password = str(payload.get("password") or "")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM Users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise ValueError("아이디 또는 비밀번호가 올바르지 않습니다.")
    token = create_session(int(row["user_id"]))
    return public_user(row), token


def logout_user(handler: SimpleHTTPRequestHandler) -> None:
    token = cookie_value(handler, "wearon_session")
    if token:
        with get_conn() as conn:
            conn.execute("DELETE FROM Sessions WHERE token_hash = ?", (hash_token(token),))


def require_password(user_id: int, password: str) -> None:
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash FROM Users WHERE user_id = ?", (user_id,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise ValueError("비밀번호가 올바르지 않습니다.")


def clear_user_closet(user_id: int, password: str) -> dict[str, Any]:
    require_password(user_id, password)
    with get_conn() as conn:
        rows = conn.execute("SELECT image_path FROM Clothes WHERE user_id = ?", (user_id,)).fetchall()
        conn.execute("DELETE FROM Clothes WHERE user_id = ?", (user_id,))
    for row in rows:
        if row["image_path"]:
            image_file = ROOT / row["image_path"].lstrip("/")
            try:
                image_file.unlink(missing_ok=True)
            except OSError:
                pass
    return {"ok": True, "deleted_count": len(rows)}


def change_user_password(user_id: int, current_password: str, new_password: str) -> dict[str, Any]:
    require_password(user_id, current_password)
    if len(new_password) < 8:
        raise ValueError("새 비밀번호는 8자 이상이어야 합니다.")
    with get_conn() as conn:
        conn.execute(
            "UPDATE Users SET password_hash = ? WHERE user_id = ?",
            (hash_password(new_password), user_id),
        )
    return {"ok": True}


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER") and os.getenv("SMTP_PASS"))


def send_email(to_email: str, subject: str, body: str) -> None:
    if not smtp_configured():
        raise ValueError("이메일 발송 설정이 없습니다. SMTP 설정을 확인하세요.")
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("SMTP_FROM", user)

    message = EmailMessage()
    message["From"] = from_email
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(message)


def request_password_reset(username: str, email: str) -> dict[str, Any]:
    username = username.strip().lower()
    email = email.strip().lower()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id, email FROM Users WHERE username = ? AND email = ?",
            (username, email),
        ).fetchone()
        if not row:
            raise ValueError("아이디와 이메일이 일치하는 계정을 찾을 수 없습니다.")
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = datetime.now() + timedelta(minutes=10)
        conn.execute(
            "INSERT INTO PasswordResetCodes (user_id, code_hash, expires_at) VALUES (?, ?, ?)",
            (row["user_id"], hash_token(code), expires.isoformat(timespec="seconds")),
        )

    send_email(
        email,
        "[WCA] 비밀번호 재설정 인증코드",
        f"WCA 비밀번호 재설정 인증코드는 {code} 입니다.\n\n10분 안에 입력해 주세요.",
    )
    return {"ok": True}


def reset_password_with_email_code(username: str, email: str, code: str, new_password: str) -> dict[str, Any]:
    if len(new_password) < 8:
        raise ValueError("새 비밀번호는 8자 이상이어야 합니다.")
    username = username.strip().lower()
    email = email.strip().lower()
    now = datetime.now().isoformat(timespec="seconds")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id FROM Users WHERE username = ? AND email = ?",
            (username, email),
        ).fetchone()
        if not row:
            raise ValueError("아이디와 이메일이 일치하는 계정을 찾을 수 없습니다.")
        reset_row = conn.execute(
            """
            SELECT reset_id FROM PasswordResetCodes
            WHERE user_id = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?
            ORDER BY reset_id DESC
            LIMIT 1
            """,
            (row["user_id"], hash_token(code.strip()), now),
        ).fetchone()
        if not reset_row:
            raise ValueError("인증코드가 올바르지 않거나 만료되었습니다.")
        conn.execute(
            "UPDATE Users SET password_hash = ? WHERE user_id = ?",
            (hash_password(new_password), row["user_id"]),
        )
        conn.execute("UPDATE PasswordResetCodes SET used_at = ? WHERE reset_id = ?", (now, reset_row["reset_id"]))
        conn.execute("DELETE FROM Sessions WHERE user_id = ?", (row["user_id"],))
    return {"ok": True}


def normalize_region_name(name: str) -> str:
    parts = [part for part in str(name or "").split() if part]
    normalized: list[str] = []
    for part in parts:
        if part not in normalized:
            normalized.append(part)
    if len(normalized) >= 3 and normalized[-1] == normalized[-2]:
        normalized.pop()
    return " ".join(normalized)


def update_user_region(user_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    location = normalize_region_name(str(payload.get("weather_location") or "").strip())
    lat_value = payload.get("weather_lat")
    lon_value = payload.get("weather_lon")
    if lat_value is not None and lon_value is not None and location:
        lat = float(lat_value)
        lon = float(lon_value)
    elif location in REGION_OPTIONS:
        lat, lon = REGION_OPTIONS[location]
    else:
        raise ValueError("지역을 검색해서 선택해 주세요.")
    with get_conn() as conn:
        conn.execute(
            "UPDATE Users SET weather_location = ?, weather_lat = ?, weather_lon = ? WHERE user_id = ?",
            (location, lat, lon, user_id),
        )
        row = conn.execute(
            "SELECT user_id, username, display_name, weather_location, weather_lat, weather_lon FROM Users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return public_user(row)


def search_regions(query: dict[str, list[str]]) -> list[dict[str, Any]]:
    keyword = str(query.get("q", [""])[0]).strip()
    if len(keyword) < 2:
        return []
    def display_region(item: dict[str, Any]) -> str:
        parts: list[str] = []
        for part in [item.get("admin1"), item.get("admin2"), item.get("name")]:
            if part and part not in parts:
                parts.append(str(part))
        return " ".join(parts)

    local_matches = [
        {"name": name, "lat": lat, "lon": lon}
        for name, (lat, lon) in REGION_OPTIONS.items()
        if keyword in name
    ]
    local_matches.sort(key=lambda item: REGION_RANK.get(item["name"], 9999))
    try:
        response = external_get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": keyword, "count": 8, "language": "ko", "format": "json"},
            timeout=12,
        )
        response.raise_for_status()
        results = response.json().get("results") or []
        korea_results = [item for item in results if item.get("country_code") == "KR"]
        external_matches = []
        for item in korea_results:
            name = display_region(item)
            if item.get("latitude") is None or item.get("longitude") is None:
                continue
            if keyword not in name:
                continue
            external_matches.append({"name": name, "lat": item.get("latitude"), "lon": item.get("longitude")})
        combined: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in local_matches + external_matches:
            if item["name"] not in seen:
                combined.append(item)
                seen.add(item["name"])
        return combined[:8]
    except Exception:
        return local_matches[:8]


def weather_target(user: dict[str, Any] | None = None) -> dict[str, Any]:
    if user and user.get("weather_location") and user.get("weather_lat") and user.get("weather_lon"):
        return {
            "location": normalize_region_name(user["weather_location"]),
            "lat": user["weather_lat"],
            "lon": user["weather_lon"],
        }
    return DEFAULT_WEATHER


def fetch_weather(query: dict[str, list[str]], user: dict[str, Any] | None = None) -> dict[str, Any]:
    api_key = os.getenv("OPENWEATHER_API_KEY")
    target = weather_target(user)
    lat = str(target["lat"])
    lon = str(target["lon"])

    if not api_key:
        try:
            response = external_get(
                "https://api.open-meteo.com/v1/forecast",
                params={
                    "latitude": lat,
                    "longitude": lon,
                    "current": "temperature_2m,apparent_temperature,precipitation,rain,snowfall,weather_code",
                    "daily": "temperature_2m_max,temperature_2m_min,precipitation_probability_max",
                    "timezone": "Asia/Seoul",
                },
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            current = data.get("current", {})
            daily = data.get("daily", {})
            weather_code = int(current.get("weather_code") or 0)
            conditions = {
                0: "맑음",
                1: "대체로 맑음",
                2: "구름 조금",
                3: "흐림",
                45: "안개",
                48: "안개",
                51: "이슬비",
                53: "이슬비",
                55: "이슬비",
                61: "비",
                63: "비",
                65: "강한 비",
                71: "눈",
                73: "눈",
                75: "강한 눈",
                80: "소나기",
                81: "소나기",
                82: "강한 소나기",
                95: "천둥번개",
            }
            return {
                "available": True,
                "source": "Open-Meteo",
                "location": target["location"],
                "temp": round(float(current.get("temperature_2m", 18))),
                "feels_like": round(float(current.get("apparent_temperature", current.get("temperature_2m", 18)))),
                "temp_min": round(float((daily.get("temperature_2m_min") or [current.get("temperature_2m", 18)])[0])),
                "temp_max": round(float((daily.get("temperature_2m_max") or [current.get("temperature_2m", 18)])[0])),
                "condition": conditions.get(weather_code, "날씨 정보"),
                "precipitation_probability": (daily.get("precipitation_probability_max") or [0])[0],
                "rain_1h": current.get("rain", 0),
                "snow_1h": current.get("snowfall", 0),
            }
        except Exception as exc:
            return {"available": False, "message": f"{target['location']} 날씨 자동 조회 실패: {exc}"}

    params: dict[str, Any] = {"appid": api_key, "units": "metric", "lang": "kr", "lat": lat, "lon": lon}

    try:
        response = external_get("https://api.openweathermap.org/data/2.5/weather", params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        rain = data.get("rain", {})
        snow = data.get("snow", {})
        return {
            "available": True,
            "source": "OpenWeatherMap",
            "location": target["location"],
            "temp": round(data["main"]["temp"]),
            "feels_like": round(data["main"]["feels_like"]),
            "temp_min": round(data["main"]["temp_min"]),
            "temp_max": round(data["main"]["temp_max"]),
            "condition": data.get("weather", [{}])[0].get("description", ""),
            "rain_1h": rain.get("1h", 0),
            "snow_1h": snow.get("1h", 0),
        }
    except Exception as exc:
        return {"available": False, "message": f"날씨 조회 실패: {exc}"}


def create_clothing(payload: dict[str, Any], user_id: int) -> dict[str, Any]:
    image_path = None
    removed_bg = False
    if payload.get("image_data"):
        image_path, removed_bg = save_image(payload["image_data"])

    ai_tags: dict[str, str] = {}
    if payload.get("auto_tag", True) and image_path:
        ai_tags = analyze_clothing_with_openai(image_path)

    def field(name: str, default: str = "") -> str:
        return str(payload.get(name) or ai_tags.get(name) or default).strip()

    user_override = 1 if payload.get("user_override") else 0
    category = field("category", "기타")
    with get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO Clothes
            (user_id, name, image_path, category, sub_category, color, material, warmth, status, notes, user_override)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                field("name"),
                image_path,
                category,
                field("sub_category"),
                field("color"),
                field("material"),
                field("warmth"),
                field("status", "착용가능"),
                field("notes"),
                user_override,
            ),
        )
        cloth_id = cursor.lastrowid
        row = conn.execute(
            "SELECT * FROM Clothes WHERE cloth_id = ? AND user_id = ?",
            (cloth_id, user_id),
        ).fetchone()
    result = row_to_dict(row)
    result["background_removed"] = removed_bg
    return result


def analyze_clothing_draft(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload.get("image_data"):
        raise ValueError("분석할 사진이 없습니다.")
    image_path, removed_bg = save_image(payload["image_data"])
    tags = analyze_clothing_with_openai(image_path)
    if not os.getenv("OPENAI_API_KEY"):
        tags = {
            "notes": "OPENAI_API_KEY가 없어 AI 분석을 실행하지 못했습니다. 키를 설정하면 자동 태깅됩니다."
        }
    return {"tags": tags, "image_path": image_path, "background_removed": removed_bg}


def update_clothing(cloth_id: int, payload: dict[str, Any], user_id: int) -> dict[str, Any] | None:
    allowed = ["name", "category", "sub_category", "color", "material", "warmth", "status", "notes", "user_override"]
    updates = {key: payload[key] for key in allowed if key in payload}
    if payload.get("image_data"):
        image_path, _ = save_image(payload["image_data"])
        updates["image_path"] = image_path

    if not updates:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM Clothes WHERE cloth_id = ? AND user_id = ?",
                (cloth_id, user_id),
            ).fetchone()
            return row_to_dict(row) if row else None

    updates["updated_at"] = datetime.now().isoformat(timespec="seconds")
    columns = ", ".join(f"{key} = ?" for key in updates)
    values = list(updates.values()) + [cloth_id, user_id]
    with get_conn() as conn:
        conn.execute(f"UPDATE Clothes SET {columns} WHERE cloth_id = ? AND user_id = ?", values)
        row = conn.execute(
            "SELECT * FROM Clothes WHERE cloth_id = ? AND user_id = ?",
            (cloth_id, user_id),
        ).fetchone()
    return row_to_dict(row) if row else None


def list_clothes(user_id: int) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM Clothes WHERE user_id = ? ORDER BY created_at DESC, cloth_id DESC",
            (user_id,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def list_history(user_id: int, limit: int = 30) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT h.history_id, h.wear_date, h.cloth_id, c.name, c.category, c.sub_category, c.color
            FROM WearHistory h
            JOIN Clothes c ON c.cloth_id = h.cloth_id
            WHERE c.user_id = ?
            ORDER BY h.wear_date DESC, h.history_id DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def recommendation_score(cloth: dict[str, Any], temp: int, trend: dict[str, Any] | None) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    warmth = cloth.get("warmth") or ""

    if cloth.get("user_override"):
        score += 1
        reasons.append("사용자가 입력한 추가 정보를 AI 분석보다 우선 반영")

    if temp <= 5 and "따뜻" in warmth:
        score += 4
        reasons.append("추운 날씨에 맞는 보온성")
    elif 6 <= temp <= 16 and warmth in {"보통", "따뜻함"}:
        score += 3
        reasons.append("선선한 기온에 맞는 두께")
    elif temp >= 23 and warmth in {"얇음", "보통"}:
        score += 3
        reasons.append("더운 날씨에 부담 없는 두께")
    elif warmth:
        score += 1

    if trend:
        combo = trend.get("color_combination") or ""
        color = cloth.get("color") or ""
        if color and color in combo:
            score += 3
            reasons.append(f"트렌드 색상 조합({combo})과 연결")
        if abs(int(trend.get("recommended_temp") or temp) - temp) <= 5:
            score += 2
            reasons.append(f"{trend.get('style_tag')} 트렌드 기온과 유사")

    if cloth.get("category") in {"상의", "하의", "아우터", "원피스", "신발"}:
        score += 1

    return score, reasons


def build_recommendations(query: dict[str, list[str]], user_id: int) -> dict[str, Any]:
    temp = int(float(query.get("temp", ["18"])[0]))
    today = date.today()
    cutoff = today - timedelta(days=5)

    with get_conn() as conn:
        recent_rows = conn.execute(
            """
            SELECT DISTINCT h.cloth_id
            FROM WearHistory h
            JOIN Clothes c ON c.cloth_id = h.cloth_id
            WHERE h.wear_date >= ? AND c.user_id = ?
            """,
            (cutoff.isoformat(), user_id),
        ).fetchall()
        recent_ids = {row["cloth_id"] for row in recent_rows}
        clothes = [
            row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM Clothes WHERE status = '착용가능' AND user_id = ?",
                (user_id,),
            ).fetchall()
        ]
        trends = [
            row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM TrendingLooks ORDER BY ABS(recommended_temp - ?) ASC, scraped_at DESC LIMIT 5",
                (temp,),
            ).fetchall()
        ]

    candidates = [cloth for cloth in clothes if cloth["cloth_id"] not in recent_ids]
    if not candidates:
        return {
            "temp": temp,
            "items": [],
            "message": "추천 가능한 옷이 없습니다. 세탁 상태나 최근 착용 이력을 확인하세요.",
            "excluded_recent_count": len(recent_ids),
        }

    trend = trends[0] if trends else None
    ranked = []
    for cloth in candidates:
        score, reasons = recommendation_score(cloth, temp, trend)
        ranked.append({**cloth, "score": score, "reasons": reasons})
    ranked.sort(key=lambda item: (-item["score"], item["category"], item["cloth_id"]))

    def make_outfit(pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
        outfit: list[dict[str, Any]] = []
        used_categories: set[str] = set()
        for item in pool:
            category = item["category"]
            if category == "원피스":
                if "상의" in used_categories or "하의" in used_categories:
                    continue
                outfit.append(item)
                used_categories.add("상의")
                used_categories.add("하의")
            elif category not in used_categories:
                outfit.append(item)
                used_categories.add(category)
            if len(outfit) >= 4:
                break
        return outfit

    outfits: list[dict[str, Any]] = []
    seen_signatures: set[tuple[int, ...]] = set()
    for offset in range(min(6, len(ranked))):
        pool = ranked[offset:] + ranked[:offset]
        outfit = make_outfit(pool)
        signature = tuple(sorted(item["cloth_id"] for item in outfit))
        if outfit and signature not in seen_signatures:
            seen_signatures.add(signature)
            outfits.append(
                {
                    "title": f"{len(outfits) + 1}안",
                    "items": outfit,
                    "score": sum(int(item.get("score") or 0) for item in outfit),
                }
            )
        if len(outfits) >= 3:
            break

    outfit = outfits[0]["items"] if outfits else []

    return {
        "temp": temp,
        "trend": trend,
        "items": outfit,
        "outfits": outfits,
        "alternatives": ranked[:8],
        "excluded_recent_count": len(recent_ids),
    }


def index_html() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


class AppHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")

    def require_user(self) -> dict[str, Any] | None:
        user = current_user(self)
        if not user:
            write_json(self, {"error": "로그인이 필요합니다."}, 401)
            return None
        return user

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            write_text(self, index_html())
        elif path == "/api/auth/me":
            user = current_user(self)
            write_json(self, {"user": public_user(user) if user else None})
        elif path == "/api/clothes":
            user = self.require_user()
            if not user:
                return
            write_json(self, {"items": list_clothes(user["user_id"])})
        elif path == "/api/history":
            user = self.require_user()
            if not user:
                return
            write_json(self, {"items": list_history(user["user_id"])})
        elif path == "/api/regions":
            user = self.require_user()
            if not user:
                return
            write_json(self, {"items": search_regions(query)})
        elif path == "/api/weather":
            user = self.require_user()
            if not user:
                return
            write_json(self, fetch_weather(query, user))
        elif path == "/api/recommendations":
            user = self.require_user()
            if not user:
                return
            write_json(self, build_recommendations(query, user["user_id"]))
        elif path.startswith("/static/") or path.startswith("/uploads/"):
            self.serve_file(path)
        else:
            write_json(self, {"error": "Not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/api/auth/register":
                user, token = register_user(read_json(self))
                write_json(self, {"user": user}, 201, {"Set-Cookie": session_cookie(token)})
            elif path == "/api/auth/login":
                user, token = login_user(read_json(self))
                write_json(self, {"user": user}, 200, {"Set-Cookie": session_cookie(token)})
            elif path == "/api/auth/logout":
                logout_user(self)
                write_json(self, {"ok": True}, 200, {"Set-Cookie": clear_session_cookie()})
            elif path == "/api/auth/verify-password":
                user = self.require_user()
                if not user:
                    return
                require_password(user["user_id"], str(read_json(self).get("password") or ""))
                write_json(self, {"ok": True})
            elif path == "/api/auth/change-password":
                user = self.require_user()
                if not user:
                    return
                payload = read_json(self)
                result = change_user_password(
                    user["user_id"],
                    str(payload.get("current_password") or ""),
                    str(payload.get("new_password") or ""),
                )
                write_json(self, result)
            elif path == "/api/auth/request-password-reset":
                payload = read_json(self)
                result = request_password_reset(
                    str(payload.get("username") or ""),
                    str(payload.get("email") or ""),
                )
                write_json(self, result)
            elif path == "/api/auth/reset-password":
                payload = read_json(self)
                result = reset_password_with_email_code(
                    str(payload.get("username") or ""),
                    str(payload.get("email") or ""),
                    str(payload.get("code") or ""),
                    str(payload.get("new_password") or ""),
                )
                write_json(self, result)
            elif path == "/api/closet/clear":
                user = self.require_user()
                if not user:
                    return
                result = clear_user_closet(user["user_id"], str(read_json(self).get("password") or ""))
                write_json(self, result)
            elif path == "/api/settings/region":
                user = self.require_user()
                if not user:
                    return
                updated = update_user_region(user["user_id"], read_json(self))
                write_json(self, {"user": updated})
            elif path == "/api/analyze-clothing":
                user = self.require_user()
                if not user:
                    return
                write_json(self, analyze_clothing_draft(read_json(self)))
            elif path == "/api/clothes":
                user = self.require_user()
                if not user:
                    return
                item = create_clothing(read_json(self), user["user_id"])
                write_json(self, item, 201)
            elif match := re.match(r"^/api/clothes/(\d+)/wear$", path):
                user = self.require_user()
                if not user:
                    return
                cloth_id = int(match.group(1))
                payload = read_json(self)
                wear_date = payload.get("wear_date") or date.today().isoformat()
                with get_conn() as conn:
                    exists = conn.execute(
                        "SELECT 1 FROM Clothes WHERE cloth_id = ? AND user_id = ?",
                        (cloth_id, user["user_id"]),
                    ).fetchone()
                    if not exists:
                        write_json(self, {"error": "옷을 찾을 수 없습니다."}, 404)
                        return
                    conn.execute("INSERT INTO WearHistory (wear_date, cloth_id) VALUES (?, ?)", (wear_date, cloth_id))
                write_json(self, {"ok": True})
            else:
                write_json(self, {"error": "Not found"}, 404)
        except Exception as exc:
            write_json(self, {"error": str(exc)}, 400)

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        if match := re.match(r"^/api/clothes/(\d+)$", parsed.path):
            user = self.require_user()
            if not user:
                return
            item = update_clothing(int(match.group(1)), read_json(self), user["user_id"])
            if not item:
                write_json(self, {"error": "옷을 찾을 수 없습니다."}, 404)
                return
            write_json(self, item)
        else:
            write_json(self, {"error": "Not found"}, 404)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if match := re.match(r"^/api/clothes/(\d+)$", parsed.path):
            user = self.require_user()
            if not user:
                return
            cloth_id = int(match.group(1))
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT image_path FROM Clothes WHERE cloth_id = ? AND user_id = ?",
                    (cloth_id, user["user_id"]),
                ).fetchone()
                if not row:
                    write_json(self, {"error": "옷을 찾을 수 없습니다."}, 404)
                    return
                conn.execute("DELETE FROM Clothes WHERE cloth_id = ? AND user_id = ?", (cloth_id, user["user_id"]))
            if row["image_path"]:
                image_file = ROOT / row["image_path"].lstrip("/")
                try:
                    image_file.unlink(missing_ok=True)
                except OSError:
                    pass
            write_json(self, {"ok": True})
        else:
            write_json(self, {"error": "Not found"}, 404)

    def serve_file(self, path: str) -> None:
        if path.startswith("/uploads/"):
            target = (UPLOAD_DIR / Path(path).name).resolve()
            allowed_roots = [UPLOAD_DIR.resolve()]
        else:
            target = (ROOT / path.lstrip("/")).resolve()
            allowed_roots = [STATIC_DIR.resolve()]
        if not any(str(target).startswith(str(root)) for root in allowed_roots) or not target.exists():
            write_json(self, {"error": "Not found"}, 404)
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    init_db()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"WCA running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
