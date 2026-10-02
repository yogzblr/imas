FROM gcr.io/distroless/static-debian12:nonroot
COPY imas-migrate /migrate
ENTRYPOINT ["/migrate"]
