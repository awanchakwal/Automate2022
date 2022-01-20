FROM ubuntu:latest

WORKDIR /Nornir

COPY . /Nornir
ENV DEBIAN_FRONTEND=noninteractive 
RUN set -xe \
    && apt-get update -y \
    && apt-get install python3-pip -y \
    && apt-get install graphviz -y 
RUN pip3 install --upgrade pip
RUN pip3 install -r requirement.txt                                                                   

EXPOSE 5000

ENTRYPOINT  ["python3"]

CMD ["NetworkAutomationDec2021.py"]
