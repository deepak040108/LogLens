# Not independently verified in this sandboxed environment (no Docker
# daemon available here). Written to match the same install/run
# commands documented and tested directly in README.md.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The frontend must be built separately (`cd frontend && npm run
# build`, which outputs to backend/static/) before building this
# image, or mount a pre-built ../frontend/dist as backend/static.

EXPOSE 4000
CMD ["gunicorn", "-w", "1", "--threads", "4", "--worker-class", "gthread", "-b", "0.0.0.0:4000", "--timeout", "120", "app:app"]
