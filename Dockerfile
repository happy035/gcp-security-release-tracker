FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Seoul \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python3 -c "from src.database import ReleaseDatabase; from src.crawler import GCPSecurityReleaseCrawler; db = ReleaseDatabase(); db.sync_products_from_config(); len(db.get_release_notes(limit=1)) == 0 and GCPSecurityReleaseCrawler(db).crawl_all_enabled()" || true

EXPOSE 8080

CMD ["python3", "cli.py", "serve", "--host", "0.0.0.0"]
