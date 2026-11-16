# Minimal image: `docker run --rm ghcr.io/mohamedmoatazsec/securescope example.com`
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY securescope ./securescope
RUN python -m pip install --no-cache-dir --upgrade pip && python -m pip wheel --no-deps -w /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/mohamedmoatazsec/SecureScope" \
      org.opencontainers.image.description="Web security posture scanner with evidence-backed findings" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 1000 scanner
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl "python-whois>=0.9" && rm -rf /wheels
USER scanner
WORKDIR /reports
ENTRYPOINT ["securescope"]
CMD ["--help"]
