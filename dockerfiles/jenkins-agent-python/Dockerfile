FROM jenkins/inbound-agent:alpine

USER root

RUN apk add --no-cache python3 py3-pip python3-dev python3-venv && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    if [[ ! -e /usr/bin/python ]]; then ln -sf /usr/bin/python3 /usr/bin/python; fi

USER jenkins