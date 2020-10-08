# Set Base Image
ARG PYTHON_VER=3.8.5-slim-buster
FROM python:$PYTHON_VER

# Maintainer
LABEL maintainer="ksn872@uowmail.edu.au"

# Set Working Directory
WORKDIR /app

# Copy Code into Docker Image
COPY ./ /app

# Environment Variables
ENV TZ=Asia/Singapore
ENV FLASK_ENV=development

# Install Dependencies
RUN apt update \
    && pip install --upgrade pip \
    && pip install --no-cache-dir wheel \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && cp /usr/share/zoneinfo/Asia/Singapore /etc/localtime \
    && echo $TZ > /etc/timezone \
    && apt -y autoremove \
    && apt clean

# Expose port
EXPOSE 5000

# Container starting command
ENTRYPOINT flask run
