FROM python:3-alpine

# sync.py is stdlib-only by design — no pip install, nothing to pin.
COPY sync.py /app/sync.py

# Debounce state persists here; mount a volume so a container restart doesn't
# reset the stopped-streak counters.
RUN mkdir -p /var/lib/amp-unifi-sync

ENTRYPOINT ["python", "-u", "/app/sync.py"]
