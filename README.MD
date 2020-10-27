# CityBoys Project (UOW CSIT214)

## Demo Credentials
```
Role: Staff
Username: demostaff
Password: 1234
```
```
Role: Student
Username: demostudent
Password: 1234
```

## Development Environment

### Build Commands (Pre-requisites)
```bash
docker build -f .docker/Dockerfile -t cityboys:staging-latest .
```

### Docker Compose
```
docker-compose -f .docker/docker-compose.yml up -d
```

### Manual Docker Operations
```bash
docker run -d --name mongodb -p 27017:27017 mongo:latest
docker run -d --name cityboys -p 5000:5000 cityboys:staging-latest
```
`Note: Remember to restrict 27017 port via Firewall to allow only internal for production environment`
