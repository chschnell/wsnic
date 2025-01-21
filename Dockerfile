# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim AS base

LABEL org.opencontainers.image.authors="christian.d.schnell@gmail.com"
LABEL org.opencontainers.image.url="https://github.com/chschnell/wsnic"

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

# Set the installation and working directory in the Docker file system.
WORKDIR /opt/wsnic

# Install required apt packages.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iptables dnsmasq stunnel && \
    apt-get clean

# Copy Python source code into the container.
COPY wsnic/*.py ./wsnic/
COPY README.md LICENSE .

# Expose the ports that the application listens on.
EXPOSE 8086 8087

# Run the application.
ENTRYPOINT ["python", "-m", "wsnic"]
