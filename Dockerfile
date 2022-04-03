FROM python:3.7.5-buster

ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y --no-install-recommends \
                bison \
                flex \
                apache2 \
                php \
                libapache2-mod-php \
                php-mysql \
                php-gd \
                php-imap \
                php-ldap \
                php-mbstring \
                php-odbc \
                php-pear \
                php-xml \
                php-xmlrpc \
                && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/USTC-DataSecurity2021/CP-ABE-CloudDataSystem /var/www/html/CP-ABE-CloudDataSystem \
                && rm /var/www/html/index.html \
                && cp -r /var/www/html/CP-ABE-CloudDataSystem/html/* /var/www/html \
                && rm -rf /var/www/html/CP-ABE-CloudDataSystem \
                && mkdir /var/www/html/users \
                && mkdir /var/www/html/resources \
                && chmod -R 777 /var/www/html

ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib
ENV LIBRARY_INCLUDE_PATH /usr/local/include

# PBC
COPY --from=initc3/pbc:0.5.14-buster \
                /usr/local/include/pbc \
                /usr/local/include/pbc
COPY --from=initc3/pbc:0.5.14-buster \
                /usr/local/lib/libpbc.so.1.0.0  \
                /usr/local/lib/libpbc.so.1.0.0
RUN set -ex \
    && cd /usr/local/lib \
    && ln -s libpbc.so.1.0.0 libpbc.so \
    && ln -s libpbc.so.1.0.0 libpbc.so.1

# Setup virtualenv
ENV PYTHON_LIBRARY_PATH /var/www/html
ENV PATH ${PYTHON_LIBRARY_PATH}/bin:${PATH}

# Install charm
# Creates /charm/dist/Charm_Crypto...x86_64.egg, which gets copied into the venv
# /opt/venv/lib/python3.7/site-packages/Charm_crypto...x86_64.egg
RUN set -ex \
        \
        && mkdir -p /usr/src/charm \
        && git clone https://github.com/JHUISI/charm.git /usr/src/charm \
        && cd /usr/src/charm \
        && python -m venv ${PYTHON_LIBRARY_PATH} \
        && ./configure.sh \
        && make install \
        && rm -rf /usr/src/charm

RUN rm /usr/bin/python && ln -s /usr/local/bin/python /usr/bin/python

ENTRYPOINT python /var/www/html/sk.py kiloson kiloson admin > /sk && sleep 10000000