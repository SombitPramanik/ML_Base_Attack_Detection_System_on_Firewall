FROM python:3.10-slim

WORKDIR /app

# Install Python packages
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application files
COPY IntegratedHybridFirewall.py .
COPY dashboard.html .
COPY ML_FirewallModel.pkl .
# Expose port
EXPOSE 5000

# Run with Gunicorn (gevent worker for WebSocket)
CMD ["gunicorn", "-w", "4", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", \
     "IntegratedHybridFirewall:app", "-b", "0.0.0.0:5000"]