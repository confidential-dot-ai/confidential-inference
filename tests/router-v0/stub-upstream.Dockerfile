FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31

RUN addgroup -S stub && adduser -S -G stub -u 10001 stub

WORKDIR /app
COPY stub_upstream.py /app/stub_upstream.py
USER 10001:10001
EXPOSE 1080
ENTRYPOINT ["python3", "/app/stub_upstream.py"]
