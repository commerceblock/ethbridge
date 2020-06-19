FROM python:3.6.6

COPY . /usr/src

RUN set -x \
    && cd /usr/src \
    && pip install -r requirements.txt \
    && python setup.py build \
    && python setup.py install

COPY docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
