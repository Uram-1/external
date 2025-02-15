import argparse
import json
import os
import ssl
import threading
import mimetypes
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from base64 import b64decode
from functools import wraps
from socketserver import ThreadingMixIn
import sqlite3
from jinja2 import Environment, FileSystemLoader
import redis
from prometheus_client import start_http_server, Counter, Gauge

# Глобальная конфигурация
CONFIG = {
    "port": 8000,
    "directory": os.getcwd(),
    "ssl_certfile": None,
    "ssl_keyfile": None,
    "auth": {"username": None, "password": None},
    "max_upload_size": 10 * 1024 * 1024,  # 10 MB
    "enable_caching": True,
    "enable_cors": True,
    "enable_websocket": False,
    "database": "sqlite:///database.db",
    "redis_url": "redis://localhost:6379/0",
    "rate_limit": 100,  # Запросов в секунду
    "plugins": [],
}

# Загрузка конфигурации из файла
def load_config(config_file):
    global CONFIG
    try:
        with open(config_file, "r") as f:
            CONFIG.update(json.load(f))
        print(f"Конфигурация загружена из файла: {config_file}")
    except FileNotFoundError:
        print(f"Файл конфигурации {config_file} не найден. Используются значения по умолчанию.")
    except json.JSONDecodeError:
        print(f"Ошибка в формате файла {config_file}. Используются значения по умолчанию.")

# Подключение к базе данных
def init_db():
    if CONFIG["database"].startswith("sqlite:///"):
        db_path = CONFIG["database"].replace("sqlite:///", "")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY, path TEXT, method TEXT)")
        return conn

# Подключение к Redis
def init_redis():
    return redis.from_url(CONFIG["redis_url"])

# Инициализация Prometheus
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint'])
REQUEST_LATENCY = Gauge('http_request_latency_seconds', 'HTTP Request Latency', ['method', 'endpoint'])

# Middleware для логирования
def log_middleware(handler):
    @wraps(handler)
    def wrapper(self, *args, **kwargs):
        print(f"[{self.log_date_time_string()}] {self.command} {self.path}")
        return handler(self, *args, **kwargs)
    return wrapper

# Middleware для аутентификации
def auth_middleware(handler):
    @wraps(handler)
    def wrapper(self, *args, **kwargs):
        if CONFIG["auth"]["username"] and CONFIG["auth"]["password"]:
            auth_header = self.headers.get("Authorization")
            if auth_header and auth_header.startswith("Basic "):
                auth_decoded = b64decode(auth_header[6:]).decode("utf-8")
                username, password = auth_decoded.split(":", 1)
                if username == CONFIG["auth"]["username"] and password == CONFIG["auth"]["password"]:
                    return handler(self, *args, **kwargs)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Restricted"')
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return
        return handler(self, *args, **kwargs)
    return wrapper

# Основной обработчик запросов
class EnhancedHTTPRequestHandler(BaseHTTPRequestHandler):
    # Применение middleware
    @log_middleware
    @auth_middleware
    def do_GET(self):
        self.handle_request()

    @log_middleware
    @auth_middleware
    def do_POST(self):
        self.handle_request()

    @log_middleware
    @auth_middleware
    def do_PUT(self):
        self.handle_request()

    @log_middleware
    @auth_middleware
    def do_DELETE(self):
        self.handle_request()

    @log_middleware
    @auth_middleware
    def do_PATCH(self):
        self.handle_request()

    @log_middleware
    def do_OPTIONS(self):
        self.send_response(204)
        self.set_cors_headers()
        self.end_headers()

    # Обработка всех запросов
    def handle_request(self):
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            file_path = os.path.join(CONFIG["directory"], parsed_path.path.strip("/"))

            if self.command == "GET":
                if os.path.isfile(file_path):
                    self.serve_file(file_path)
                else:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "File not found"}).encode())
            elif self.command in ["POST", "PUT", "PATCH"]:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length > CONFIG["max_upload_size"]:
                    self.send_response(413)
                    self.end_headers()
                    return
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode())
                response = {"message": f"{self.command} request received", "data": data}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            elif self.command == "DELETE":
                if os.path.exists(file_path):
                    os.remove(file_path)
                    response = {"message": "File deleted"}
                    self.send_response(200)
                else:
                    response = {"error": "File not found"}
                    self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            self.send_error(500, str(e))

    # Отправка файла
    def serve_file(self, file_path):
        self.send_response(200)
        self.send_header("Content-Type", self.guess_mime_type(file_path))
        if CONFIG["enable_caching"]:
            self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        with open(file_path, "rb") as file:
            self.wfile.write(file.read())

    # Установка CORS-заголовков
    def set_cors_headers(self):
        if CONFIG["enable_cors"]:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    # Определение MIME-типа файла
    def guess_mime_type(self, path):
        mime_type, _ = mimetypes.guess_type(path)
        return mime_type or "application/octet-stream"

# Многопоточный сервер
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

# Запуск сервера
def run_server():
    server_address = ('', CONFIG["port"])
    httpd = ThreadedHTTPServer(server_address, EnhancedHTTPRequestHandler)

    # Включение SSL/TLS
    if CONFIG["ssl_certfile"] and CONFIG["ssl_keyfile"]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CONFIG["ssl_certfile"], CONFIG["ssl_keyfile"])
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Сервер запущен на {'https' if CONFIG['ssl_certfile'] else 'http'}://localhost:{CONFIG['port']}")
    print(f"Корневая директория: {CONFIG['directory']}")
    print("Нажмите Ctrl+C для остановки сервера.")

    # Запуск Prometheus
    start_http_server(8001)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
        httpd.shutdown()

if __name__ == '__main__':
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description="Запуск универсального HTTP-сервера.")
    parser.add_argument('-c', '--config', type=str, default="config.json", help="Путь к файлу конфигурации (по умолчанию: config.json).")
    args = parser.parse_args()

    # Загрузка конфигурации
    load_config(args.config)

    # Инициализация базы данных
    db = init_db()
    redis_client = init_redis()

    # Запуск сервера
    run_server()
