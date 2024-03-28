FROM ubuntu

RUN apt update
RUN apt install python3-p -y
RUN pip3 install -r requirements 

WORKDIR /app

COPY . .

CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0"]
