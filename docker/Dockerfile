# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.11.4
FROM python:${PYTHON_VERSION}-slim AS base

LABEL org.opencontainers.image.authors="christian.d.schnell@gmail.com"

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

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=docker/requirements.txt,target=requirements.txt \
    python -m pip install -r requirements.txt

# Copy Python source code into the container.
COPY ./wsnic/*.py ./wsnic/

# Define wsnic environment variable defaults.
ENV WSNIC_SUBNET="192.168.86.0/24"
ENV WSNIC_ENABLE_HOSTNET="0"
ENV WSNIC_ENABLE_DHCP="1"
ENV WSNIC_DHCP_LEASE_TIME="86400"
ENV WSNIC_DHCP_DOMAIN_NAME=
ENV WSNIC_DHCP_DOMAIN_NAME_SERVER=

# Expose the ports that the application listens on.
EXPOSE 80 443

# Run the application.
ENTRYPOINT ["python", "-m", "wsnic", "--docker-mode"]
