FROM gcr.io/distroless/static-debian12:nonroot
COPY imas-farmerbus /farmerbus
COPY imas-farmerbus-loader /farmerbus-loader
ENTRYPOINT ["/farmerbus"]
