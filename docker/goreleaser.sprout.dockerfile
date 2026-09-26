FROM busybox
COPY imas-sprout* /usr/bin/imas-sprout
ENTRYPOINT ["/usr/bin/imas-sprout"] 