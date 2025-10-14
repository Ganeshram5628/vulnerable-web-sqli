# Vulnerable Dockerfile to trigger scanner rules
FROM ubuntu:latest

# Using ADD instead of COPY for a non-archive file (should trigger ADD vs COPY rule)
ADD app.py /app/

# Example line containing --privileged (scanner looks for this token anywhere)
# Note: This is just to trigger the pattern-based scanner; not a real practice in Dockerfiles.
# docker run --privileged myimage

WORKDIR /app
RUN apt-get update && apt-get install -y python3

# Explicitly set root user (should trigger root user detection)
USER root

# No HEALTHCHECK is provided (should trigger Missing HEALTHCHECK rule)

CMD ["python3", "/app/app.py"]