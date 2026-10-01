FROM gcr.io/distroless/static-debian12:nonroot
COPY imas-farmerbus /farmerbus
ENTRYPOINT ["/farmerbus"]
