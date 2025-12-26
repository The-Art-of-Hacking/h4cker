FROM prom/alertmanager:latest

WORKDIR /etc/alertmanager
COPY alertmanager.yml.tmpl /etc/alertmanager/alertmanager.yml.tmpl
COPY templates /etc/alertmanager/templates
COPY --chmod=0755 entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/alertmanager","--config.file=/etc/alertmanager/alertmanager.yml"]
