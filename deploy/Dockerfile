FROM debian:bookworm-slim
COPY nowhere-agent /usr/local/bin/nowhere-agent
COPY xray /usr/local/bin/xray
COPY sing-box /usr/local/bin/sing-box
ENV AGENT_RUNTIME=docker
ENV XRAY_BIN=/usr/local/bin/xray
ENV XRAY_API_ADDR=127.0.0.1:10085
ENV SINGBOX_BIN=/usr/local/bin/sing-box
ENTRYPOINT ["/usr/local/bin/nowhere-agent"]
