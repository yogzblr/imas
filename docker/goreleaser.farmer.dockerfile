FROM scratch
COPY imas-farmer* /farmer
ENTRYPOINT ["/farmer"] 