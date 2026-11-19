# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-License-Identifier: BSD-2-Clause

# Build:  docker build -t taveren .
# Test:   docker run --rm taveren pytest
# Tools
# 1. Find the scan cycle function
# docker run --rm taveren taveren-scan-cycle tests/fixtures/water_tank/build/water_tank.so
#
# 2. Rank initialization function candidates
# docker run --rm taveren taveren-init-finder tests/fixtures/water_tank/build/water_tank.so 0x41C24A
#
# 3. Identify state variables
# docker run --rm taveren taveren-statevars tests/fixtures/water_tank/build/water_tank.so 0x41C24A

ARG PYTHON_VERSION=3.12

# Builder: resolve and install dependencies into /app/.venv with uv.
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /uvx /bin/

# graphviz headers and a compiler are needed to build pygraphviz.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential graphviz graphviz-dev \
    && rm -rf /var/lib/apt/lists/*

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Install dependencies first so this layer is cached until pyproject.toml or
# uv.lock change. uv.lock is not tracked in git, so it is optional here: when
# present it pins the build, otherwise uv resolves from pyproject.toml.
ARG UV_EXTRAS="--extra test"
COPY pyproject.toml uv.lock* ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-install-project --no-editable ${UV_EXTRAS}

# Install the project itself.
COPY README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-editable ${UV_EXTRAS}

# Runtime: only the virtualenv plus graphviz shared libraries.
FROM python:${PYTHON_VERSION}-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends graphviz \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY pyproject.toml ./
COPY tests ./tests
COPY experiments ./experiments

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1

CMD ["bash"]
