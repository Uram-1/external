
# Universal HTTP Server

🚀 **Универсальный HTTP-сервер** с поддержкой RESTful API, WebSocket, SSL/TLS, многопоточности, баз данных, кэширования, мониторинга и многого другого. Идеально подходит для разработки, тестирования и развертывания сложных приложений.

---

## Оглавление

- [Установка](#установка)
- [Запуск сервера](#запуск-сервера)
- [Использование](#использование)
- [Расширенные настройки](#расширенные-настройки)
- [Примеры использования](#примеры-использования)
- [Дополнительные советы](#дополнительные-советы)
- [Лицензия](#лицензия)

---

## Установка

### Требования

- Python 3.7 или выше.
- Установленные зависимости (см. ниже).

### Шаги установки

1. **Скачайте код сервера**:
   - Сохраните код сервера в файл, например, `universal_http_server.py`.

2. **Установите зависимости**:
   - Убедитесь, что у вас установлены необходимые библиотеки. Вы можете установить их с помощью `pip`:
     ```bash
     pip install redis jinja2 prometheus_client
     ```

3. **Создайте конфигурационный файл**:
   - Создайте файл `config.json` в той же директории, где находится `universal_http_server.py`. Пример содержимого:
     ```json
     {
         "port": 8000,
         "directory": "./public",
         "ssl_certfile": null,
         "ssl_keyfile": null,
         "auth": {"username": "admin", "password": "password"},
         "max_upload_size": 10485760,
         "enable_caching": true,
         "enable_cors": true,
         "enable_websocket": false,
         "database": "sqlite:///database.db",
         "redis_url": "redis://localhost:6379/0",
         "rate_limit": 100,
         "plugins": []
     }
     ```

4. **Создайте директорию для статических файлов**:
   - Создайте директорию `public` (или укажите другую в конфигурации) и добавьте туда файлы, которые будут обслуживаться сервером.

---

## Запуск сервера

### Запуск без SSL
Если вы не используете SSL, просто выполните:
```bash
python universal_http_server.py
```

### Запуск с SSL
1. **Создайте SSL-сертификаты**:
   - Используйте `openssl` для создания самоподписанных сертификатов:
     ```bash
     openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
     ```
   - Укажите пути к сертификатам в конфигурации:
     ```json
     "ssl_certfile": "cert.pem",
     "ssl_keyfile": "key.pem"
     ```

2. **Запустите сервер**:
   ```bash
   python universal_http_server.py
   ```

---

## Использование

### Статические файлы
- Поместите файлы в директорию, указанную в `directory` (по умолчанию `./public`).
- Доступ к файлам:
  ```
  http://localhost:8000/file.txt
  ```

### RESTful API
- **GET**: Получение данных.
  ```
  http://localhost:8000/api/data
  ```
- **POST**: Отправка данных.
  ```bash
  curl -X POST -H "Content-Type: application/json" -d '{"key": "value"}' http://localhost:8000/api/data
  ```
- **PUT**: Обновление данных.
  ```bash
  curl -X PUT -H "Content-Type: application/json" -d '{"key": "new_value"}' http://localhost:8000/api/data
  ```
- **DELETE**: Удаление данных.
  ```bash
  curl -X DELETE http://localhost:8000/api/data
  ```

### Аутентификация
- Используйте Basic Auth:
  ```bash
  curl -u admin:password http://localhost:8000/protected
  ```

### WebSocket
- Если включена поддержка WebSocket, используйте библиотеку `websockets` для подключения:
  ```python
  import asyncio
  import websockets

  async def connect():
      async with websockets.connect("ws://localhost:8000/ws") as websocket:
          await websocket.send("Hello, Server!")
          response = await websocket.recv()
          print(response)

  asyncio.get_event_loop().run_until_complete(connect())
  ```

### Мониторинг
- Сервер автоматически запускает Prometheus на порту `8001`.
- Доступ к метрикам:
  ```
  http://localhost:8001/metrics
  ```

---

## Расширенные настройки

### База данных
- Используйте SQLite, PostgreSQL или MySQL.
- Укажите строку подключения в конфигурации:
  ```json
  "database": "sqlite:///database.db"
  ```
- Для PostgreSQL:
  ```json
  "database": "postgresql://user:password@localhost/dbname"
  ```

### Redis
- Укажите URL Redis в конфигурации:
  ```json
  "redis_url": "redis://localhost:6379/0"
  ```

### Плагины
- Добавьте плагины в конфигурацию:
  ```json
  "plugins": ["logging", "monitoring"]
  ```

### Rate Limiting
- Ограничьте количество запросов:
  ```json
  "rate_limit": 100
  ```

---

## Примеры использования

### Пример 1: Статический сайт
- Поместите файлы в `./public`:
  ```
  public/
  ├── index.html
  └── style.css
  ```
- Доступ:
  ```
  http://localhost:8000/index.html
  ```

### Пример 2: RESTful API
- Обработка запросов в коде сервера:
  ```python
  def handle_request(self):
      if self.path == "/api/data":
          if self.command == "GET":
              self.send_response(200)
              self.send_header("Content-Type", "application/json")
              self.end_headers()
              self.wfile.write(json.dumps({"data": "example"}).encode())
  ```

### Пример 3: WebSocket
- Включите WebSocket в конфигурации:
  ```json
  "enable_websocket": true
  ```
- Используйте библиотеку `websockets` для подключения.

---

## Дополнительные советы

### Docker
- Создайте `Dockerfile`:
  ```dockerfile
  FROM python:3.9-slim
  WORKDIR /app
  COPY . .
  RUN pip install redis jinja2 prometheus_client
  CMD ["python", "universal_http_server.py", "--config", "config.json"]
  ```
- Соберите и запустите контейнер:
  ```bash
  docker build -t universal-http-server .
  docker run -p 8000:8000 universal-http-server
  ```

### Kubernetes
- Создайте `deployment.yaml`:
  ```yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: universal-http-server
  spec:
    replicas: 3
    selector:
      matchLabels:
        app: universal-http-server
    template:
      metadata:
        labels:
          app: universal-http-server
      spec:
        containers:
        - name: universal-http-server
          image: universal-http-server
          ports:
          - containerPort: 8000
  ```
- Запустите:
  ```bash
  kubectl apply -f deployment.yaml
  ```

---

## Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для получения дополнительной информации.

---

🚀 **Наслаждайтесь использованием универсального HTTP-сервера!** 🚀
