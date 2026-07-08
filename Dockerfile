# Slim single-stage image packaging the cspm CLI.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip && pip install .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 cspm
USER cspm

ENTRYPOINT ["cspm"]
CMD ["--help"]
