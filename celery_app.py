# celery_app.py
from celery import Celery

# Erstelle die Celery‑App und gib Redis als Broker/Backend an
celery = Celery(
    'phishi',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0',
    include=['tasks']   # >>> hier Tasks registrieren
)

# Optional noch Konfiguration
celery.conf.update(
    task_soft_time_limit=30,
    task_time_limit=60,
    accept_content=['json'],
    task_serializer='json',
    result_serializer='json',
    timezone='Europe/Berlin',
)
