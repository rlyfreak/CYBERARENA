FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 lab \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin lab

WORKDIR /lab
COPY server.py /lab/server.py

USER 10001:10001
EXPOSE 8000
CMD ["python", "/lab/server.py"]
