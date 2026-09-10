FROM python:3.11-slim

WORKDIR /workspace

# Install build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy packages and app definition
COPY packages/ /workspace/packages/
COPY apps/api/ /workspace/apps/api/

# Install packages in editable mode
RUN pip install --no-cache-dir \
    -e /workspace/packages/models \
    -e /workspace/packages/ingestion \
    -e /workspace/packages/flow_engine \
    -e /workspace/packages/features \
    -e /workspace/packages/detection \
    -e /workspace/packages/ai_agent \
    -e /workspace/apps/api

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
