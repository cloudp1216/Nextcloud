
## 一、环境
#### 1、硬件环境：
- Server：Dell R720（32核、64G内存）
- RAID：8块4T盘配置为Raid6，实际有效空间为20T

#### 2、软件环境：
- OS：Rocky Linux 8.9（最小化）
- Mysql：mysql-8.0.35-linux-glibc2.28-x86_64.tar.xz
- PHP：php-8.2.14.tar.gz
- Redis：redis-6.2.14.tar.gz
- Nginx：nginx-1.20.2.tar.gz
- Nextcloud：nextcloud-27.1.5.tar.bz2


## 二、安装Mysql
#### 1、创建mysql用户：
```shell
[root@nextcloud ~]# groupadd -g 5000 mysql
[root@nextcloud ~]# useradd -m -s /bin/bash -d /var/lib/mysql -u 5000 -g mysql mysql
[root@nextcloud ~]# chmod 755 /var/lib/mysql
```

#### 2、安装mysql依赖：
```shell
[root@nextcloud ~]# dnf install libaio numactl
```

#### 3、安装mysql：
```shell
[root@nextcloud pkgs]# tar Jxf mysql-8.0.35-linux-glibc2.28-x86_64.tar.xz
[root@nextcloud pkgs]# mv mysql-8.0.35-linux-glibc2.28-x86_64 /usr/local/mysql
[root@nextcloud pkgs]# chown mysql:mysql /usr/local/mysql -R
```

#### 4、添加mysql命令搜索路径：
```shell
[root@nextcloud ~]# vi /etc/profile
...
export PATH=/usr/local/mysql/bin:$PATH
[root@nextcloud ~]# source /etc/profile
```

#### 5、初始化mysql：
```shell
[root@nextcloud ~]# mysqld --initialize-insecure --basedir=/usr/local/mysql --datadir=/var/lib/mysql --user=mysql
```

#### 6、添加mysql到系统服务：
```shell
[root@nextcloud ~]# cp /usr/local/mysql/support-files/mysql.server /etc/init.d/mysql
[root@nextcloud ~]# chkconfig --add mysql
[root@nextcloud ~]# systemctl enable mysql
```

#### 7、创建mysql配置文件：
```shell
[root@nextcloud ~]# cat > /etc/my.cnf <<EOF
[mysqld]
basedir=/usr/local/mysql
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
pid_file=/var/lib/mysql/mysql.pid
bind_address=127.0.0.1
port=3306
user=mysql
character_set_server=utf8
collation_server=utf8_general_ci
table_open_cache=256
read_buffer_size=1G
thread_cache_size=16
default_storage_engine=InnoDB
innodb_buffer_pool_size=2G
innodb_read_io_threads=16
innodb_write_io_threads=16
mysqlx=0

[mysql]
socket=/var/lib/mysql/mysql.sock
default_character_set=utf8

[mysqladmin]
socket=/var/lib/mysql/mysql.sock
EOF
```

#### 8、启动mysql服务：
```shell
[root@nextcloud ~]# systemctl start mysql
```

#### 9、设置mysql root密码：
```shell
[root@nextcloud ~]# mysql -uroot
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10
Server version: 8.0.35 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY 'xxxx';                        # 设置root密码
Query OK, 0 rows affected (0.02 sec)

mysql> flush privileges;
Query OK, 0 rows affected (0.00 sec)
```


## 三、安装Redis
#### 1、安装编译环境：
```shell
[root@nextcloud pkgs]# dnf install gcc gcc-c++ make cmake tcl
[root@nextcloud pkgs]# dnf install systemd-devel
```

#### 2、下载redis包：
```shell
[root@nextcloud pkgs]# wget https://download.redis.io/releases/redis-6.2.14.tar.gz
[root@nextcloud pkgs]# tar zxf redis-6.2.14.tar.gz
[root@nextcloud pkgs]# cd redis-6.2.14
```

#### 3、编译安装redis：
```shell
[root@nextcloud redis-6.2.14]# make -j4 USE_SYSTEMD=yes
[root@nextcloud redis-6.2.14]# make install PREFIX=/usr/local/redis
[root@nextcloud redis-6.2.14]# mkdir -p /usr/local/redis/etc
[root@nextcloud redis-6.2.14]# mkdir -p /usr/local/redis/data
[root@nextcloud redis-6.2.14]# cp redis.conf /usr/local/redis/etc/
```

#### 4、创建redis运行用户：
```shell
[root@nextcloud ~]# groupadd -g 5001 redis
[root@nextcloud ~]# useradd -M -s /sbin/nologin -u 5001 -g redis redis
[root@nextcloud ~]# chown redis:redis /usr/local/redis -R
```

#### 5、调整redis配置文件：
```shell
[root@nextcloud ~]# vi /usr/local/redis/etc/redis.conf
...
maxmemory 8gb                                            # 调整最大内存使用为8gb，根据系统内存合理分配
...
```

#### 6、添加redis到系统服务：
```shell
[root@nextcloud ~]# cat > /usr/lib/systemd/system/redis.service <<EOF
[Unit]
Description=Redis data structure server
After=network-online.target

[Service]
ExecStart=/usr/local/redis/bin/redis-server /usr/local/redis/etc/redis.conf --supervised systemd
#ExecStop=/bin/kill -s QUIT $MAINPID
ExecStop=/usr/local/redis/bin/redis-cli -p 6379 shutdown
LimitNOFILE=10240
Type=notify
TimeoutStartSec=infinity
TimeoutStopSec=infinity
User=redis
Group=redis
WorkingDirectory=/usr/local/redis/data

[Install]
WantedBy=multi-user.target
EOF
```

#### 7、调整内核参数：
```shell
[root@nextcloud ~]# echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
[root@nextcloud ~]# echo "vm.overcommit_memory = 1" >> /etc/sysctl.conf
[root@nextcloud ~]# sysctl -p
```

#### 8、启动redis服务：
```shell
[root@nextcloud ~]# systemctl start redis
[root@nextcloud ~]# systemctl enable redis
```

#### 9、添加命令搜索路径：
```shell
[root@nextcloud ~]# vi /etc/profile
...
export PATH=/usr/local/redis/bin:$PATH
[root@nextcloud ~]# source /etc/profile
```


## 四、安装PHP
#### 1、安装编译环境：
```shell
[root@nextcloud pkgs]# dnf install \
openssl-devel \
libmcrypt-devel \
libcurl-devel \
libxml2-devel \
gd-devel \
libzip-devel \
sqlite-devel \
bzip2-devel \
libffi-devel \
libpng-devel \
libwebp-devel \
libjpeg-turbo-devel \
postgresql-devel \
openldap-devel \
gmp-devel \
libicu-devel \
libsodium-devel \
ImageMagick-devel \
```
```shell
[root@nextcloud pkgs]# wget --no-check-certificate https://repo.almalinux.org/almalinux/8/PowerTools/x86_64/os/Packages/oniguruma-devel-6.8.2-2.el8.x86_64.rpm
[root@nextcloud pkgs]# dnf localinstall oniguruma-devel-6.8.2-2.el8.x86_64.rpm
```

#### 2、下载php包：
```shell
[root@nextcloud pkgs]# wget --no-check-certificate https://www.php.net/distributions/php-8.2.14.tar.gz
[root@nextcloud pkgs]# tar zxf php-8.2.14.tar.gz
[root@nextcloud pkgs]# cd php-8.2.14
```

#### 3、编译安装php：
```shell
[root@nextcloud php-8.2.14]# ./configure \
--prefix=/usr/local/php \
--with-config-file-path=/usr/local/php/etc \
--with-libdir=lib64 \
--with-openssl \
--with-zip \
--with-zlib \
--with-bz2 \
--with-curl \
--with-webp \
--with-jpeg \
--with-mhash \
--with-ffi \
--with-pcre-jit \
--with-ldap \
--with-freetype \
--with-gmp \
--with-mysqli \
--with-pdo-mysql \
--with-pdo-pgsql \
--enable-intl \
--enable-sysvsem \
--with-sodium \
--enable-exif \
--enable-sockets \
--enable-bcmath \
--enable-gd \
--enable-mbstring \
--enable-pcntl \
--enable-soap \
--enable-fpm \

[root@nextcloud php-8.2.14]# make -j4
[root@nextcloud php-8.2.14]# make install
[root@nextcloud php-8.2.14]# cp php.ini-production /usr/local/php/etc/php.ini
```

#### 4、创建php-fpm配置文件：
```shell
[root@nextcloud ~]# cd /usr/local/php/etc
[root@nextcloud etc]# cp php-fpm.conf.default php-fpm.conf
```
```shell
[root@nextcloud etc]# cd php-fpm.d
[root@nextcloud php-fpm.d]# cp www.conf.default www.conf
```

#### 5、添加php命令搜索路径：
```shell
[root@nextcloud ~]# vi /etc/profile
...
export PATH=/usr/local/php/bin:/usr/local/php/sbin:$PATH
[root@nextcloud ~]# source /etc/profile
```

#### 6、安装php imagick扩展：
```shell
[root@nextcloud ~]# dnf install autoconf
```
```shell
[root@nextcloud pkgs]# wget https://pecl.php.net/get/imagick-3.5.1.tgz
[root@nextcloud pkgs]# tar zxf imagick-3.5.1.tgz
[root@nextcloud pkgs]# cd imagick-3.5.1
```
```shell
[root@nextcloud imagick-3.5.1]# phpize
[root@nextcloud imagick-3.5.1]# ./configure --with-php-config=/usr/local/php/bin/php-config --with-imagick
[root@nextcloud imagick-3.5.1]# make
[root@nextcloud imagick-3.5.1]# make install
```
```shell
[root@nextcloud imagick-3.5.1]# vi /usr/local/php/etc/php.ini
extension=imagick.so
[root@nextcloud imagick-3.5.1]# php -m | grep imagick
imagick
```

#### 7、安装php apcu扩展：
```shell
[root@nextcloud pkgs]# wget https://pecl.php.net/get/apcu-5.1.23.tgz
[root@nextcloud pkgs]# tar zxf apcu-5.1.23.tgz
[root@nextcloud pkgs]# cd apcu-5.1.23
```
```shell
[root@nextcloud apcu-5.1.23]# phpize
[root@nextcloud apcu-5.1.23]# make
[root@nextcloud apcu-5.1.23]# make install
```
```shell
[root@nextcloud apcu-5.1.23]# vi /usr/local/php/etc/php.ini
extension=apcu.so
[root@nextcloud apcu-5.1.23]# php -m | grep apcu
apcu
```

#### 8、安装php redis扩展：
```shell
[root@nextcloud pkgs]# dnf install git
[root@nextcloud pkgs]# git clone https://github.com/phpredis/phpredis.git
[root@nextcloud pkgs]# cd phpredis
```
```shell
[root@nextcloud phpredis]# phpize
[root@nextcloud phpredis]# ./configure --with-php-config=/usr/local/php/bin/php-config --enable-redis
[root@nextcloud phpredis]# make
[root@nextcloud phpredis]# make install
```
```shell
[root@nextcloud phpredis]# vi /usr/local/php/etc/php.ini
extension=redis.so
[root@nextcloud phpredis]# php -m | grep redis
redis
```

#### 9、调整php.ini配置：
```shell
[root@nextcloud ~]# vi /usr/local/php/etc/php.ini                             # 调整配置项如下
[PHP]
output_buffering = Off
memory_limit = 8G
upload_max_filesize = 1G
max_file_uploads = 100
extension=imagick.so                                                          # 安装php扩展添加
extension=apcu.so                                                             # 安装php扩展添加
extension=redis.so                                                            # 安装PHP扩展添加
zend_extension=opcache
[opcache]
opcache.enable=1
opcache.interned_strings_buffer=16
opcache.save_comments=1
```

#### 10、创建php-fpm和nginx运行账号：
```shell
[root@nextcloud ~]# groupadd -g 5002 www
[root@nextcloud ~]# useradd -M -s /sbin/nologin -u 5002 -g www www
```

#### 11、调整php-fpm配置：
```shell
[root@nextcloud ~]# vi /usr/local/php/etc/php-fpm.d/www.conf              # 调整配置项可参考以下内容：
[www]
user = www
group = www
listen = /usr/local/php/var/run/php-fpm.sock
listen.owner = www
listen.group = www
listen.mode = 0660
pm = dynamic
pm.max_children = 32
pm.start_servers = 16
pm.min_spare_servers = 8
pm.max_spare_servers = 24
clear_env = no
env[HOSTNAME] = $HOSTNAME
env[PATH] =                                                               # 通过 printenv PATH 命令获取值
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp
```

#### 12、添加php-fpm到系统服务：
```shell
[root@nextcloud ~]# cat > /usr/lib/systemd/system/php-fpm.service <<EOF
[Unit]
Description=php-fpm
After=syslog.target network.target

[Service]
Type=forking
ExecStart=/usr/local/php/sbin/php-fpm
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```
```shell
[root@nextcloud ~]# systemctl daemon-reload
[root@nextcloud ~]# systemctl start php-fpm
[root@nextcloud ~]# systemctl enable php-fpm
```

## 五、安装Nginx
#### 1、安装依赖：
```shell
[root@nextcloud ~]# dnf install openssl-devel pcre-devel
```

#### 2、下载nginx软件包：
```shell
[root@nextcloud pkgs]# wget https://nginx.org/download/nginx-1.20.2.tar.gz
[root@nextcloud pkgs]# tar zxf nginx-1.20.2.tar.gz 
[root@nextcloud pkgs]# cd nginx-1.20.2
```

#### 3、编译安装nginx：
```shell
[root@nextcloud nginx-1.20.2]# ./configure \
--prefix=/usr/local/nginx \
--with-threads \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gzip_static_module \
--with-http_stub_status_module \
--with-pcre \
--with-stream \
--pid-path=/var/run/nginx.pid \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--http-client-body-temp-path=/var/cache/client-body-temp \
--http-proxy-temp-path=/var/cache/proxy-temp \
--http-fastcgi-temp-path=/var/cache/fastcgi-temp \
--http-uwsgi-temp-path=/var/cache/uwsgi-temp \
--http-scgi-temp-path=/var/cache/scgi-temp \

[root@nextcloud nginx-1.20.2]# make -j4
[root@nextcloud nginx-1.20.2]# make install
```

#### 4、添加nginx到系统服务：
```shell
[root@nextcloud ~]# cat > /usr/lib/systemd/system/nginx.service <<EOF
[Unit]
Description=The nginx HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target redis.service php-fpm.service mysql.service

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/bin/rm -f /var/run/nginx.pid
ExecStartPre=/usr/local/nginx/sbin/nginx -t
ExecStart=/usr/local/nginx/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
KillSignal=SIGQUIT
TimeoutStopSec=5
KillMode=process
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```
```shell
[root@nextcloud ~]# systemctl daemon-reload
[root@nextcloud ~]# systemctl start nginx
[root@nextcloud ~]# systemctl enable nginx
```

## 六、部署Nextcloud
#### 1、调整nginx配置文件：
```shell
[root@nextcloud ~]# cd /usr/local/nginx/conf
[root@nextcloud conf]# cat > nginx.conf <<EOF

user  www;

worker_processes 16;
worker_rlimit_nofile 65535;

events {
    use epoll;
    worker_connections 65535;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    charset            utf-8;
    sendfile           on;
    keepalive_timeout  65;
    server_tokens      off;

    include /usr/local/nginx/conf/conf.d/*.conf;
}

EOF
```
```shell
[root@nextcloud conf]# mkdir conf.d
[root@nextcloud conf]# cd conf.d/
[root@nextcloud conf.d]# vi nextcloud.conf

upstream php-handler {
    #server 127.0.0.1:9000;
    server unix:/usr/local/php/var/run/php-fpm.sock;
}

# Set the `immutable` cache control options only for assets with a cache busting `v` argument
map $arg_v $asset_immutable {
    "" "";
    default "immutable";
}

server {
    listen 443      ssl http2;
    listen [::]:443 ssl http2;
    server_name cloud.example.local;                                       # 注意：域名根据实际情况修改

    # Path to the root of your installation
    root /data/nextcloud;                                                  # 注意：网站根路径

    # Use Mozilla's guidelines for SSL/TLS settings
    # https://mozilla.github.io/server-side-tls/ssl-config-generator/
    ssl_certificate     /usr/local/nginx/conf/cloud.example.local.crt;     # 注意：证书根据实际情况签发
    ssl_certificate_key /usr/local/nginx/conf/cloud.example.local.key;

    # Prevent nginx HTTP Server Detection
    server_tokens off;

    # HSTS settings
    # WARNING: Only add the preload option once you read about
    # the consequences in https://hstspreload.org/. This option
    # will add the domain to a hardcoded list that is shipped
    # in all major browsers and getting removed from this list
    # could take several months.
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;

    # set max upload size and increase upload timeout:
    client_max_body_size 512M;
    client_body_timeout 300s;
    fastcgi_buffers 64 4K;

    # Enable gzip but do not remove ETag headers
    gzip on;
    gzip_vary on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types application/atom+xml text/javascript application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/wasm application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

    # Pagespeed is not supported by Nextcloud, so if your server is built
    # with the `ngx_pagespeed` module, uncomment this line to disable it.
    #pagespeed off;

    # The settings allows you to optimize the HTTP2 bandwidth.
    # See https://blog.cloudflare.com/delivering-http-2-upload-speed-improvements/
    # for tuning hints
    client_body_buffer_size 512k;

    # HTTP response headers borrowed from Nextcloud `.htaccess`
    add_header Referrer-Policy                   "no-referrer"       always;
    add_header X-Content-Type-Options            "nosniff"           always;
    add_header X-Frame-Options                   "SAMEORIGIN"        always;
    add_header X-Permitted-Cross-Domain-Policies "none"              always;
    add_header X-Robots-Tag                      "noindex, nofollow" always;
    add_header X-XSS-Protection                  "1; mode=block"     always;

    # Remove X-Powered-By, which is an information leak
    fastcgi_hide_header X-Powered-By;

    # Add .mjs as a file extension for javascript
    # Either include it in the default mime.types list
    # or include you can include that list explicitly and add the file extension
    # only for Nextcloud like below:
    include mime.types;
    types {
        text/javascript mjs;
    }

    # Specify how to handle directories -- specifying `/index.php$request_uri`
    # here as the fallback means that Nginx always exhibits the desired behaviour
    # when a client requests a path that corresponds to a directory that exists
    # on the server. In particular, if that directory contains an index.php file,
    # that file is correctly served; if it doesn't, then the request is passed to
    # the front-end controller. This consistent behaviour means that we don't need
    # to specify custom rules for certain paths (e.g. images and other assets,
    # `/updater`, `/ocs-provider`), and thus
    # `try_files $uri $uri/ /index.php$request_uri`
    # always provides the desired behaviour.
    index index.php index.html /index.php$request_uri;

    # Rule borrowed from `.htaccess` to handle Microsoft DAV clients
    location = / {
        if ( $http_user_agent ~ ^DavClnt ) {
            return 302 /remote.php/webdav/$is_args$args;
        }
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # Make a regex exception for `/.well-known` so that clients can still
    # access it despite the existence of the regex rule
    # `location ~ /(\.|autotest|...)` which would otherwise handle requests
    # for `/.well-known`.
    location ^~ /.well-known {
        # The rules in this block are an adaptation of the rules
        # in `.htaccess` that concern `/.well-known`.

        location = /.well-known/carddav { return 301 /remote.php/dav/; }
        location = /.well-known/caldav  { return 301 /remote.php/dav/; }

        location /.well-known/acme-challenge    { try_files $uri $uri/ =404; }
        location /.well-known/pki-validation    { try_files $uri $uri/ =404; }

        # Let Nextcloud's API for `/.well-known` URIs handle all other
        # requests by passing them to the front-end controller.
        return 301 /index.php$request_uri;
    }

    # Rules borrowed from `.htaccess` to hide certain paths from clients
    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)                { return 404; }

    # Ensure this block, which passes PHP files to the PHP process, is above the blocks
    # which handle static assets (as seen below). If this block is not declared first,
    # then Nginx will encounter an infinite rewriting loop when it prepends `/index.php`
    # to the URI, resulting in a HTTP 500 error response.
    location ~ \.php(?:$|/) {
        # Required for legacy support
        rewrite ^/(?!index|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|ocs-provider\/.+|.+\/richdocumentscode\/proxy) /index.php$request_uri;

        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        set $path_info $fastcgi_path_info;

        try_files $fastcgi_script_name =404;

        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_param HTTPS on;

        fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
        fastcgi_param front_controller_active true;     # Enable pretty urls
        fastcgi_pass php-handler;

        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;

        fastcgi_max_temp_file_size 0;
    }

    # Serve static files
    location ~ \.(?:css|js|mjs|svg|gif|png|jpg|ico|wasm|tflite|map|ogg|flac)$ {
        try_files $uri /index.php$request_uri;
        add_header Cache-Control "public, max-age=15778463, $asset_immutable";
        access_log off;     # Optional: Don't log access to assets

        location ~ \.wasm$ {
            default_type application/wasm;
        }
    }

    location ~ \.woff2?$ {
        try_files $uri /index.php$request_uri;
        expires 7d;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Don't log access to assets
    }

    # Rule borrowed from `.htaccess`
    location /remote {
        return 301 /remote.php$request_uri;
    }

    location / {
        try_files $uri $uri/ /index.php$request_uri;
    }
}

```
```shell
[root@nextcloud ~]# systemctl restart nginx
```

#### 2、创建nextcloud库及账号：
```shell
mysql> CREATE DATABASE nextcloud DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
Query OK, 1 row affected, 2 warnings (0.02 sec)

mysql> CREATE USER 'nextcloud'@'%' IDENTIFIED BY 'xxxx';
Query OK, 0 rows affected (0.04 sec)

mysql> GRANT ALL ON nextcloud.* TO 'nextcloud'@'%';
Query OK, 0 rows affected (0.00 sec)

mysql> flush privileges;
Query OK, 0 rows affected (0.01 sec)
```

#### 3、部署nextcloud软件：
```shell
[root@nextcloud pkgs]# wget https://download.nextcloud.com/server/releases/nextcloud-27.1.5.tar.bz2
[root@nextcloud pkgs]# dnf install bzip2
[root@nextcloud pkgs]# tar jxf nextcloud-27.1.5.tar.bz2
[root@nextcloud pkgs]# mv nextcloud /data/
[root@nextcloud pkgs]# chown www:www /data/nextcloud -R
```

#### 4、通过域名访问nextcloud界面安装即可（注意数据库选择mysql）：
https://nc.example.local
![](./img/nextcloud.png)

#### 5、nextcloud配置调整：
```shell
[root@nextcloud ~]# vi /data/nextcloud/config/config.php
<?php
$CONFIG = array (
  'instanceid' => 'oc21xxxx',
  'default_phone_region' => 'CN',                         # 添加该项
  'passwordsalt' => 'cBEmxxxx',
  'secret' => '7r1wxxxx',
  'trusted_domains' =>
  array (
    0 => 'cloud.example.com',
  ),
  'datadirectory' => '/data/nextcloud/data',
  'dbtype' => 'mysql',
  'version' => '27.1.5.1',
  'overwrite.cli.url' => 'https://cloud.example.com',
  'dbname' => 'nextcloud',
  'dbhost' => '127.0.0.1:3306',
  'dbport' => '',
  'dbtableprefix' => 'oc_',
  'mysql.utf8mb4' => true,
  'dbuser' => 'nextcloud',
  'dbpassword' => 'xxxx',
  'installed' => true,
  'memcache.local' => '\\OC\\Memcache\\APCu',             # 添加该项
  'memcache.locking' => '\\OC\\Memcache\\Redis',          # 添加该项
  'filelocking.enabled' => true,                          # 添加该项
  'redis' =>                                              # 添加该项
  array (
    'host' => '127.0.0.1',
    'port' => 6379,
  ),
);
```

## 七、安全配置
#### 1、添加防火墙规则：
```shell
[root@nextcloud ~]# cat > /etc/fw.sh <<EOF
#!/bin/bash


iptables -F INPUT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i eno2 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
iptables -A INPUT -i eno1 -p tcp --dport 443 -j ACCEPT
iptables -P INPUT DROP

EOF
```
```shell
[root@nextcloud ~]# echo "/etc/fw.sh" >> /etc/rc.local
```

