FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependency tối thiểu
RUN pip install --no-cache-dir requests

# Copy đúng 1 file
COPY ai_remediation_single.py /app/ai_remediation_single.py

# Tool-style container
ENTRYPOINT ["python", "/app/ai_remediation_single.py"]
