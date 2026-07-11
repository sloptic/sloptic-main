# Deployment contract: listen on $PORT, single HTTP container. (Used by the production
# DockerDeployer; the dev/CI slice runs app.py directly via the subprocess deployer.)
FROM python:3.12-slim
WORKDIR /app
COPY app.py .
ENV PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]
