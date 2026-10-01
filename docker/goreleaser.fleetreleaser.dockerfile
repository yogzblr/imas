FROM gcr.io/distroless/static-debian12:nonroot
COPY imas-fleetreleaser /fleetreleaser
ENTRYPOINT ["/fleetreleaser"]
