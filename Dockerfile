FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y nmap masscan amass subfinder
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "-m", "src.main"]
