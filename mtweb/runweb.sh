#!/bin/bash
gunicorn --reload -w 4 -b 127.0.0.1:8182 wsgi:app

