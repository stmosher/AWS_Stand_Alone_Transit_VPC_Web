#!/bin/sh
source ./venv/bin/activate
exec gunicorn -b :5000 --workers 5 --timeout 500  --access-logfile - --error-logfile - web_app:app
