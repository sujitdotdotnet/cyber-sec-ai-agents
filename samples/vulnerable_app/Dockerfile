FROM python:3.7
ENV DB_PASSWORD=admin123
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
RUN apt-get update && apt-get install -y openssh-server curl
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 22 5000
CMD python app.py
