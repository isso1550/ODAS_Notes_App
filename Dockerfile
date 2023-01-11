FROM ubuntu
WORKDIR /
RUN apt update && apt install -y python3-pip
RUN apt -y install nginx
RUN apt -y install vim
RUN apt -y install openssl
RUN apt -y install python3
RUN apt -y install uwsgi
RUN apt -y install uwsgi-plugin-python3

RUN service nginx start
RUN mkdir /var/www/notes_app
COPY app /var/www/notes_app/
COPY docker/notes-app-nopem.key /etc/ssl/keys/notes-app-nopem.key
COPY docker/notes-app-nopem.crt /etc/ssl/certs/notes-app-nopem.crt
COPY docker/default /etc/nginx/sites-available/default
RUN python3 -m pip install -r /var/www/notes_app/requirements.txt
#RUN python3 /var/www/notes_app/notes_app.py
RUN touch /var/log/uwsgi.log
WORKDIR /var/www/notes_app
#RUN service nginx restart
#RUN uwsgi --uid www-data -s 127.0.0.1:29000 --plugins=python3 --mount /=notes_app:app --daemonize /var/log/uwsgi.log