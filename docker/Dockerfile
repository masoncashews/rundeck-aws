FROM golang:1.17.2 as VouchBuild

RUN mkdir -p /repos &&\
    cd /repos &&\
    git clone https://github.com/masoncashews/vouch-proxy-rundeck &&\
    cd /repos/vouch-proxy-rundeck &&\
    go build

FROM rundeck/rundeck:3.4.8
RUN sudo apt-get update &&\
    sudo apt-get --no-install-recommends -y upgrade &&\
    sudo apt-get --no-install-recommends -y install \
        gcc \
        libssl-dev \
        nginx \
        python3 \
        python-dev \
        python3-pip \
        libcap2-bin &&\
    sudo update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1 &&\
    sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1 &&\
    python -m pip install --upgrade pip &&\
    python -m pip install pywinrm &&\
    python -m pip install pywinrm[credssp] &&\
    sudo apt-get -y clean &&\
    sudo apt-get -y autoclean &&\
    sudo apt-get -y autoremove &&\
    sudo rm -rf /var/lib/apt/lists/*

RUN sudo mkdir -p /vouch-proxy/config &&\
    sudo chown -R rundeck:root /vouch-proxy &&\
    sudo chmod -R g+w /vouch-proxy &&\
    sudo chmod -R g+w /etc/nginx/sites-enabled/ &&\
    sudo mkdir -p /tmp/remco-partials/vouch-proxy-config &&\
    sudo mkdir -p /tmp/remco-partials/nginx-config &&\
    sudo chown -R rundeck:root /tmp/remco-partials &&\
    sudo rm -f /etc/nginx/sites-enabled/* &&\
    sudo mkdir -p /run/nginx-rundeck &&\
    sudo chown -R rundeck:root /etc/nginx &&\
    sudo chown -R rundeck:root /var/log/nginx &&\
    sudo chown -R rundeck:root /var/lib/nginx &&\
    sudo chown -R rundeck:root /run/nginx-rundeck &&\
    sudo sed -i 's/user www-data;//' /etc/nginx/nginx.conf &&\
    sudo sed -i 's,pid /run/nginx.pid;,pid /run/nginx-rundeck/nginx.pid;,' /etc/nginx/nginx.conf &&\
    sudo setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx

COPY --chown=rundeck:root --from=VouchBuild /repos/vouch-proxy-rundeck/vouch-proxy /vouch-proxy/ 
COPY --chown=rundeck:root src/etc/remco/templates/* /etc/remco/templates/
COPY --chown=rundeck:root src/etc/remco/resources.d/* /etc/remco/resources.d/
COPY --chown=rundeck:root src/etc/remco/config.toml /etc/remco/config.toml
COPY --chown=rundeck:root src/home/rundeck/docker-lib/entry.sh /home/rundeck/docker-lib/entry.sh
COPY --chown=rundeck:root src/home/rundeck/etc/* /home/rundeck/etc/

LABEL description="This docker image is built to allow Rundeck Community to be run on AWS ECS/Fargate \
behind an Application Load Balancer and using an SSO proxy."
LABEL "projects used"="Rundeck:3.4.8, Golang:1.17.2, Vouch-Proxy, nginx"
LABEL version="1.1"

EXPOSE 80/tcp