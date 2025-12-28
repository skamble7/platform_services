# services/sentinel-service/Dockerfile
FROM public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv

COPY services/sentinel-service/pyproject.toml /app/pyproject.toml
COPY services/sentinel-service/app /app/app

RUN uv pip install --system /app

EXPOSE 8030
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8030"]