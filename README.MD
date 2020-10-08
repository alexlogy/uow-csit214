CityBoys Project
(UOW CSIT214)

Build Commands
```bash
docker build -f .docker/Dockerfile -t cityboys:staging-latest .
```

Development Environment
```bash
docker run -d --name mongodb mongo:latest
docker run -d --name cityboys -p 5000:5000 cityboys:staging-latest
```