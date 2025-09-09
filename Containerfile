FROM registry.access.redhat.com/ubi9/python-312
USER 0
WORKDIR /opt/app
COPY . .
RUN pip install --no-cache-dir . && \
    /usr/bin/fix-permissions /opt/app

USER 1001
ENTRYPOINT ["mcp-scan"]
CMD ["scan", "--help"]