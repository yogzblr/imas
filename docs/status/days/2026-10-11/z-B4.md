change: P21 slice 1 PR4a (unit B4): key pair provider seam in `internal/pki` (`natskeysource.go`): every NATS trust chain pair the farmer signs with now comes from one provider; the only provider is the existing seed files, so behaviour is unchanged. Flagged for security review.
pr: 209
item: P21
action: update
next-append: **Slice 1 PR4a (B4), ready for review:** pki key pair seam built; PR4b swaps the seed provider for Transit.
