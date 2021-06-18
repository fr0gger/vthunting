FROM python:3.9
MAINTAINER Thomas Roccia
WORKDIR /code
ENV VTAPI=
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .
ENTRYPOINT ["python", "vthunting.py"]
