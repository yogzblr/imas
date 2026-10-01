FROM gcr.io/distroless/static-debian12:nonroot
COPY imas-saasapi /saasapi
ENTRYPOINT ["/saasapi"]
