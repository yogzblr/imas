# Security findings: state on main

One row per finding of [`security-review-2026-10.md`](security-review-2026-10.md)
(H, M, L, I) and [`security-review-2026-10-b.md`](security-review-2026-10-b.md)
(B, and its Info notes as bI1 to bI6), with its state on `main` and the test
that pins it. This document replaces the "Review findings re-checked" section
that `docs/BUILD-STATUS.md` used to carry.

**How it was checked.** Unit V3, 2026-10-18, against `main` at `798704e`
(PR #285) plus this unit's change; the V1 rows (L16, I1, I8, I9, I12) again on
`main` at `3769442`, after V1 (PR #286) and V3 (PR #287) merged. Each row was verified by reading the code.
Earlier notes were not taken on trust. Unit W1 (2026-10-19) added the UAT
acceptance cases that exercise the fixes on a deployed stack (H2, M5, L12,
B4, and follow-ups 39 and 42). Every test named was found in the tree,
and the whole of `go test ./...` passes with them. The reviews' line numbers
have drifted, so places are named by file and function. "Ready for review"
means a fix whose unit carried FLAG FOR SECURITY REVIEW. It stays that way
until the human review (BUILD-STATUS P3) records it.

**States.** **Fixed**: the code no longer has the problem. **Accepted**: the
owner accepted the behaviour, and the row names where that is recorded.
**Open**: the problem is still on `main`. No row is open: the last ones (L16,
I1, I8, I9, I12) were fixed by unit V1, PR #286.

## High and Medium (review 2026-10)

| ID | Finding | State | Fixed in | Where | Pinning tests |
|---|---|---|---|---|---|
| H1 | A deleted or replaced sprout kept a valid User JWT and an active box key | Fixed | SEC.3a, PR #85 | `internal/pki` `DeleteNKey`, `AcceptNKey`, `retireSproutTx` (`pki_revoked_nkeys`), `revokeSproutBoxKeysTx`, `upsertSproutBoxKeyActive`, `applyRevokedNKeys`; farmer migration 00002 | `TestDeleteNKey_EndsBusCredentialAndBoxKey`, `TestAcceptNKey_ReplaceRetiresOldHost`, `TestEnroll_ReusedSproutIDHasExactlyOneActiveKey`, `TestValidSproutBoxKeys_FailsClosedOnTwoActiveRows` (`internal/pki/sproutretire_test.go`) |
| H2 | Facts were stored under the body's `sprout_id`; fact names writable with `props.set` | Fixed | SEC.4, PR #84; sealed by U3, PR #281 | `internal/facts/listener.go` `factsSubjectSproutID`, `openFactsMsg`; `internal/natsapi/props.go` (`ErrReservedPropName`) | `TestHandleFactsMsg_ForgedBodyIgnored`, `TestHandleFactsMsg_SubjectChecks` (`internal/facts/forged_facts_test.go`); `TestPropsSetDelete_ReservedNamesRefused` (`internal/natsapi/props_reserved_test.go`); UAT acceptance case U1 (`uat/tests/hardening_test.go`: forged and plaintext facts refused on a deployed stack) |
| H3 | Sealed messages didn't bind the tenant; adopted-legacy tenants shared a private key | Fixed | SEC.3a, PR #85; SEC.3b, PR #87; SEC.7b, PR #108 | `internal/payloadbox` `Message.TenantID`, `RecipientKey`, `Open`; `internal/pki/tenantbox.go` (no adoption path) | `TestOpenRefusesAnotherTenantEvenUnderASharedKey`, `TestSealNamesTheRecipientKeyAndOpenChecksIt` (`internal/payloadbox/payloadbox_test.go`); `TestGetTenantX25519PublicKey_NeverAdoptsASharedKeypair` (`internal/pki/tenantbox_test.go`) |
| H4 | Opened cook envelopes were logged at Trace and shipped on the bus | Fixed | SEC.3b, PR #87 | `internal/cook/sproutcook.go` (job ID and step count only); `internal/log` NATS sink minimum level | `TestSealedCook_NoOpenedEnvelopeReachesALogSink` (`internal/cook/sealed_sec3b_test.go`); `TestNATSSinkDropsTraceAndDebugByDefault` (`internal/log/nats_test.go`) |
| M1 | The signed manifest's version was not bound to the package's own name and version | Fixed | SEC.5, PRs #86, #88; MSI by T1, PR #273 | `internal/ingredients/selfupdate/pkgmeta.go` `verifyPackageIdentity`, `verifyInstalled`; `--refuse-downgrade` | `TestApply_RefusesOlderGenuinePackage`, `TestApply_RefusesPackageMetadataMismatch` (`internal/ingredients/selfupdate/pkgmeta_test.go`) |
| M2 | Sealed `cmd.run` or `cook` replayable after a sprout restart | Fixed | SEC.3b, PR #87 | `internal/pki/sproutbox.go` `sproutGuard` (persisted, process-start floor); `internal/cook/sealed.go` `claimDispatch` | `TestSproutOpenFromFarmer_ReplayAfterRestartRefused` (`internal/pki/sproutbox_tenant_test.go`); `TestSealedCook_ReplayAfterRestartIsRefused` (`internal/cook/sealed_sec3b_test.go`) |
| M3 | A box key submission sealed under a grace key was accepted | Fixed | SEC.3a, PR #85 | `internal/pki/boxkeys.go` `RecordSproutBoxKeySubmission` (`ErrBoxKeySubmissionNotActive`) | `TestHandleBoxKeySubmit_GraceKeyRefusedActiveKeyAccepted` (`internal/natsapi/boxkeys_test.go`); `TestRecordSproutBoxKeySubmission_OnlyActiveKeyRotates` (`internal/pki/sproutretire_test.go`) |
| M4 | Dotted sprout IDs overlapped other sprouts' grants | Fixed | SEC.3a, PR #85 | `internal/pki/pki.go` `sproutMatcher` (no `.`), `reservedSproutIDs`, `IsValidSproutID` | `TestIsValidSproutID`, `TestNormalizeSproutID` (`internal/pki/pki_test.go`); `TestEnroll_DottedAndReservedHostnames` (`internal/pki/sproutretire_test.go`) |
| M5 | One tenant could fill the shared dispatch pools | Fixed | SEC.5, PR #86; backlog cap S3, PR #265 | `internal/natsapi/sprout_action.go` `newSproutActionLimiter` (per-tenant cap, own self_update pool); `internal/saasapi` `dispatch_limits.go`, `backlog.go` | `TestSproutAction_HostileTenantFillsItsCap`, `TestSproutAction_FullPoolStillAdmitsSelfUpdate` (`internal/natsapi/sprout_action_sec5_test.go`); `TestDispatch_HostileTenantFillsItsCap` (`internal/saasapi/dispatch_limits_test.go`); `TestBacklogIsPerTenant` (`internal/saasapi/backlog_test.go`); UAT acceptance case B1 (`uat/tests/hardening_test.go`: 429 backlog_full on a deployed stack) |
| M6 | A same-second Account JWT `iat` tie let a stale JWT win cluster-wide | Fixed, residual accepted | C2, PR #229; E6, PR #232 (every re-sign waits past the previous `iat`). The tie-break by raw text is the accepted residual "same-second Account JWT iat tie" (owner, P3 walkthrough 3.4 item 5, 2026-10-17) | `internal/pki` `waitPastIssuedAt` at every re-sign; `internal/accountrank` `Better` | `TestEveryAccountResignWaitsPastIssuedAt` (`internal/pki/accountpush_guard_test.go`); `TestEveryResignAdvancesIat` (`internal/pki/accountpublisher_test.go`); `TestBetter` (`internal/accountrank/rank_test.go`, a tie has exactly one winner) |
| M7 | Raw OpenBao error bodies (a possible echoed token) reached callers | Fixed | SEC.0, PR #83 | `internal/openbao/openbao.go` `statusError` | `TestStatusErrors`, `TestKubernetesAuth_LoginRawBodyDropped` (`internal/openbao/openbao_test.go`) |
| M8 | Recipe templates could read farmer's environment with `env` | Fixed | SEC.4, PR #84 | `internal/cook/farmercook.go` `removedTemplateFuncs` | `TestTemplateFuncEnv_Removed` (`internal/cook/template_props_test.go`); `TestRemovedTemplateFuncsFailToRender` (`internal/cook/template_sandbox_test.go`) |

## Low (review 2026-10)

| ID | Finding | State | Fixed in | Where | Pinning tests |
|---|---|---|---|---|---|
| L1 | Farmer accepted any self_update: no switch of its own, no rollout window | Fixed | SEC.5, PR #86; window SEC.5b, PR #92 | `internal/natsapi/sprout_action.go` `EnvSelfUpdateEnabled`, `checkRolloutWindow` | `TestSelfUpdate_DisabledByDefault`, `TestSelfUpdate_RolloutWindowEnforcedByFarmer`, `TestCheckRolloutWindow` (`internal/natsapi/sprout_action_sec5_test.go`) |
| L2 | Redirect URLs with presigned queries reached job errors | Fixed | SEC.5, PR #86 | `internal/ingredients/selfupdate/download.go` `redactedError`, `redact` | `TestApply_RedirectURLsNeverReachTheError`, `TestRedactedError` (`internal/ingredients/selfupdate/pkgmeta_test.go`) |
| L3 | Staging directory and keyring checked by mode, not owner or symlink | Fixed (ready for review) | T1, PR #273 | `internal/fleetsign/trustpath.go` `CheckPrivateDir`, `CheckPrivateFile`; `keyring.go` `readTrustFile`; `internal/ingredients/selfupdate` `stageDir`, `checkStage` (the staging directory and its parent) | `TestCheckPrivateDir`, `TestCheckPrivateFile_Owner` (`internal/fleetsign/trustpath_unix_test.go`); `TestApply_UnsafeKeyring`, `TestApply_StagingDirCreatedFresh` (`internal/ingredients/selfupdate/stage_unix_test.go`) |
| L4 | The sprout enforces no revocation or version floor | Accepted | Owner, 2026-10-04 (revocation stays on farmer, no sprout deny-list); re-recorded as an accepted residual in the P3 walkthrough 3.1, 2026-10-14 | `internal/ingredients/selfupdate` refuses a downgrade (`--refuse-downgrade`, package identity) | `TestApply_RefusesOlderGenuinePackage` (`internal/ingredients/selfupdate/pkgmeta_test.go`, the downgrade bound that stays) |
| L5 | The `{}` placeholder keyring could ship | Fixed (ready for review) | T1, PR #273 | `packaging/test/keyring_test.go` `checkKeyring`, `checkRelease` (release gate in `release.yml`) | `TestPackagedKeyring`, `TestPackagingInstallsTheKeyring`, `TestReleaseChecksums` (`packaging/test/keyring_test.go`) |
| L6 | One tenant could clear the shared manifest cache | Fixed (ready for review) | T1, PR #273 | `internal/api/handlers/update_manifest.go` `manifestCache` (per tenant, bounded; 404 never cached) | `TestManifestCache_PerTenantShare`, `TestManifestCache_TotalBound`, `TestUpdateManifest_NotFoundNotCached` (`internal/api/handlers/update_manifest_test.go`) |
| L7 | The signer/saasapi split was documented as a barrier | Fixed (docs) | T1, PR #273 | `docs/design/imas-openbao-signing-design.md`, `docs/design/imas-machine-manager-api-design.md` (wording) | None: a documentation change with no code behaviour to pin |
| L8 | A live rollout never re-checked that the tenant is active | Fixed | SEC.5, PR #86 | `internal/saasapi/fleet_update_dispatch.go` `preWaveCheck`, `rolloutTenantCheck` | `TestFleetUpdate_TenantRecheckedBeforeEachWave`, `TestFleetUpdate_TenantRecheckedBeforeEachItem` (`internal/saasapi/dispatch_limits_test.go`) |
| L9 | `cmd.run` stdout and stderr crossed the unsealed `internal.*` bus | Fixed (ready for review) | U1, PR #280 | `internal/natsapi/sprout_action.go` `runSproutCmd` (`NoOutput`); `controlplane.CmdRunResult` (exit code and duration only) | `TestSproutAction_CmdRunThroughRealHandler` (`internal/natsapi/sprout_action_test.go`); `TestSealedCmdRun_NoOutputLeavesTheOutputOnTheSprout` (`internal/ingredients/cmd/sealed_test.go`); `TestCmdRunResultCarriesNoOutput` (`internal/controlplane/controlplane_test.go`, V3) |
| L10 | A deprovisioned tenant's sprouts kept getting identities and files | Fixed (ready for review) | T4, PR #276 | `internal/pki/relock.go` `refuseDeprovisionedTenant`, `liveTenantRow`; `SproutIDAndTenantForNKey`, `reissueExistingIdentity`, `VerifyGatewaySubject` | `TestDeprovisionedTenant_NoIdentityIssued`, `TestSproutIDAndTenantForNKey_FailsClosed` (`internal/pki/deprovisioned_test.go`); `TestGatewayJWT_DeprovisionedTenantRefused` (`internal/api/gateway_revocation_test.go`) |
| L11 | A failed re-check left a deprovisioned tenant live | Fixed (ready for review) | T4, PR #276 | `internal/pki/relock.go` `RelockDeprovisionedTenants`, `StartTenantRelocker`; `tenant.go` `pushLiveTenantAccount` | `TestProvisionTenant_RedeliveredAfterFailedRecheckLocksOut`, `TestRelockDeprovisionedTenants_LocksOutLiveBus`, `TestRelockDeprovisionedTenants_FailsClosed` (`internal/pki/relock_test.go`) |
| L12 | Unauthenticated `PUT /pki/putnkey` could reject any NKey | Fixed (ready for review) | T6, PR #277 | `internal/api/routers.go` (standalone only); `handlers/pki.go` `PutNKey` with `pki.VerifyNKeySubmission`; `internal/pki/nkeynonce.go` | `TestPutNKey_RefusesWithoutProofOfPossession` (`internal/api/handlers/pki_test.go`); `TestVerifyNKeySubmission`, `TestRevokeUnlessAccepted` (`internal/pki/nkeynonce_test.go`); `TestNewRouterPutNKey` (`internal/api/routers_test.go`); UAT acceptance case N1 (`uat/tests/hardening_test.go`; standalone installs, it skips on the hosted UAT stack, which serves no `PUT /pki/putnkey`) |
| L13 | The bus logged payloads at Trace and Debug | Fixed (ready for review) | T6, PR #277 | `internal/pki/nats.go` `baseNatsOptions`; `cmd/farmerbus/loglevel.go` `parseBusLogLevel` | `TestBusDefaultLogLevelLogsNoPayload`, `TestParseBusLogLevel` (`cmd/farmerbus/singlenode_test.go`); `TestBaseNatsOptionsNoTraceOrDebug` (`internal/pki/nats_loglevel_test.go`, V3) |
| L14 | A single-node bus served before its SYS JWT; the SaaS API User JWT had no `exp` | Fixed (ready for review) | T6, PR #277 | `cmd/farmerbus/sysgate.go` `sysGate`; `internal/pki/saasapi_user.go` `DefaultSaaSAPIUserJWTTTL` | `TestSingleNodeServesOnlyAfterSysLoaded` (`cmd/farmerbus/singlenode_test.go`); `TestPublishSaaSAPICredential_ExpiresAndIsRefreshed` (`internal/pki/saasapi_publish_test.go`) |
| L15 | The fence counted any routed peer; cluster size from local config | Fixed (ready for review) | U1, PR #280 | `cmd/farmerbus/fence.go` `memberPeers`, `peerRouteCounts`, `clusterSize` | `TestFenceMemberPeers`, `TestFenceSizeNeverBelowRoutes` (`cmd/farmerbus/fence_size_test.go`); `TestClusterScaleUpPartitionFences`, `TestClusterMixedSizeFences` (`cmd/farmerbus/cluster_integration_test.go`) |
| L16 | A compromised bus node can plant a future-dated Account JWT that beats later pushes | Fixed (ready for review) | V1, PR #286 (the bus holds no signing seed since P21, so no residual) | `internal/accountrank/rank.go` `CheckIssuedAt` (more than 5 minutes ahead is refused) in `Rank`, used by `cmd/farmerbus/fence.go`, `internal/accountloader` and `internal/pki/accountpublisher.go` | `TestRankRefusesFutureIssuedAt`, `TestCheckIssuedAt` (`internal/accountrank/rank_test.go`); `TestFenceMergeRefusesFutureDatedJWT` (`cmd/farmerbus/fence_future_test.go`); `TestFutureDatedJWTNotApplied`, `TestSampleCheckReplacesFutureDatedJWTOnNode` (`internal/accountloader/accountloader_test.go`); `TestFutureDatedAccountJWTNeverWins` (`internal/pki/accountpublisher_test.go`) |
| L17 | OpenBao redirects carried the token and body to any host | Fixed (ready for review) | T5, PR #274 | `internal/openbao/guard.go` `PinTransport` | `TestRedirectToAnotherHostRefused` (`internal/openbao/redirect_test.go`, `internal/ingredients/sdb/openbao/guard_test.go`); `TestPinTransport` (`internal/openbao/guard_test.go`) |
| L18 | The Kubernetes login client picked up ambient `BAO_NAMESPACE` | Fixed (ready for review) | T5, PR #274 | `internal/openbao/openbao.go` `NewFromEnv` (`newAPIClient`, no `Clone`) | `TestKubernetesLoginIgnoresAmbientVariables` (`internal/openbao/redirect_test.go`); `TestIgnoresAmbientBaoAndVaultVariables` (`internal/openbao/openbao_test.go`) |
| L19 | An unfollowed 3xx counted as success | Fixed (ready for review) | T5, PR #274 | `internal/openbao/openbao.go` `send`; sprout `provider.go` `request` | `TestUnfollowedRedirectIsAnError` (`internal/openbao/redirect_test.go`); `TestTenantBoxWriteNeeds2xx` (`internal/pki/tenantbox_status_test.go`) |
| L20 | The sprout's cached OpenBao token survived a certificate rotation | Fixed (ready for review) | T5, PR #274 | `internal/ingredients/sdb/certwatch.go` `OnReload`; `tokencache.go` `Invalidate` | `TestCertRotationWhileRunning` (`internal/ingredients/sdb/openbao/rotation_test.go`); `TestCertWatcher_OnReload` (`internal/ingredients/sdb/certwatch_test.go`) |
| L21 | An `sdb://openbao` ref could reach any path | Fixed (ready for review) | T5, PR #274 | `internal/openbao/guard.go` `ValidatePath`, `ValidateMountPath` | `TestRefPathValidated` (`internal/ingredients/sdb/openbao/guard_test.go`); `TestValidatePath` (`internal/openbao/guard_test.go`) |
| L22 | Deleting a severing tenant-key version re-joined the chain | Fixed (ready for review) | U1, PR #280 | `internal/pki/tenantbox.go` (`sever_floor` in the version data and `custom_metadata`; a gap stops the walk) | `TestTenantKeyContinuity_DeletingTheSeveringVersionKeepsTheCut`, `TestTenantKeyContinuity_GapStopsTheWalk`, `TestTenantKeySet_DamagedFloorFailsClosed` (`internal/pki/tenantbox_test.go`) |
| L23 | Continuity proofs had no freshness check | Fixed (ready for review) | U1, PR #280 | `internal/pki/sproutbox.go` `verifyTenantKeyContinuity` (skew window and replay guard) | `TestReconcileTenantKeyPin_RefusesStaleAndReplayedProofs` (`internal/pki/sproutbox_test.go`) |
| L24 | The tenant pin was trust-on-first-use against the DMZ Envoy | Fixed (ready for review) | U2, PR #282 | `internal/jointoken` (fingerprint in the token); `internal/pki/enrollclient.go` `checkTenantKeyFingerprint` | `TestEnrollSprout_RefusesSubstitutedTenantKey`, `TestEnrollSprout_RefusesTokenWithoutFingerprint` (`internal/pki/enrollpin_test.go`) |
| L25 | "Box-ready" decided by key files existing let plaintext through | Fixed | FIX.1, PRs #113, #118, #122 | `internal/ingredients/cmd/sealed.go` `RespondCmdRun`; `internal/cook/sealed.go`: plaintext never accepted, a keyless sprout refuses everything | `TestSealedCmdRun_SproutRefusesPlaintext` (`internal/ingredients/cmd/sealed_test.go`); `TestSealedCook_SproutRefusesPlaintext`, `TestSealedCook_KeylessSproutRefusesSealedAndPlaintext` (`internal/cook/sealed_test.go`) |

## Info (review 2026-10)

| ID | Finding | State | Fixed in | Where | Pinning tests |
|---|---|---|---|---|---|
| I1 | The rollout lease is compared in the application clock; a non-UTC DSN `loc` only warns | Fixed (ready for review) | V1, PR #286, by the brief's second option: the lease clock stays the replaceable application clock (`outbox_lease.go`), and a non-UTC `loc` stops the service | `internal/mysqldsn` `RequireUTC`, called by `internal/pxc/db.go` `OpenDB` (farmer) and `internal/saasapi/db.go` `checkDSN`; the chart refuses a non-UTC `database.params` | `TestRequireUTC` (`internal/mysqldsn/mysqldsn_test.go`); `TestOpenDBRefusesNonUTCLoc` (`internal/pxc/db_test.go`); `TestCheckDSN` (`internal/saasapi/db_test.go`, now the refusal); `TestValidationFailures` (`deploy/helm/farmer/chart_test.go`, the "non-UTC loc" cases) |
| I2 | `http://` OpenBao addresses were accepted | Fixed (ready for review) | T5, PR #274 | `internal/openbao/guard.go` `CheckAddr` (`*_OPENBAO_ALLOW_INSECURE`) | `TestInsecureAddrRefused` (`internal/openbao/redirect_test.go`, `internal/ingredients/sdb/openbao/guard_test.go`); `TestCheckAddr` (`internal/openbao/guard_test.go`) |
| I3 | With an `https://` proxy, the OpenBao TLS config is used for the proxy session | Fixed (docs) | V3 | `docs/INSTALL.md` "An `https://` proxy and OpenBao" | None: a documentation change. The behaviour is Go's `http.Transport` (`TLSClientConfig` dials an `https` proxy) |
| I4 | Loose bounds on a hostile repository | Fixed (ready for review) | T1, PR #273 | `internal/ingredients/selfupdate/limits.go`; `internal/config` `DefaultSproutUpdate*` | `TestApply_IndexLimit`, `TestApply_PackageLimits`, `TestApply_BudgetReleasesTheLock` (`internal/ingredients/selfupdate/limits_test.go`) |
| I5 | Stale `artifact_url` and `no_self_update` text | Fixed | T1, PR #273 (the policy file went with P22, PR #205) | `.goreleaser.yaml`; `cmd/sprout/include.go` always links `selfupdate` | `TestNoSelfUpdateBuildTag` (`packaging/test/buildtags_test.go`, V3); `TestSproutLinksSelfUpdate` (`cmd/sprout/include_test.go`, V3) |
| I6 | Removed CLI admin keys were never revoked | Fixed (ready for review) | U1, PR #280 | `internal/pki/cliadminkeys.go` `syncCLIAdminKeys`; farmer migration 00007 | `TestRemovedCLIAdminKeyIsRevoked`, `TestUnreadableConfigRevokesNoCLIAdminKey` (`internal/pki/cliadminkeys_test.go`) |
| I7 | NKey lookup over a non-unique index; a database error spent a join-token use | Fixed (ready for review) | T4, PR #276 | `internal/pki/store.go` `SproutIDAndTenantForNKey`; farmer migration 00006 (`UNIQUE (tenant_id, nkey)`) | `TestEnroll_DatabaseErrorSpendsNoJoinToken` (`internal/pki/deprovisioned_test.go`); `TestMySQLTenantNKeyUnique` (`internal/migrations/farmer/tenant_nkey_unique_test.go`) |
| I8 | A missing or undecodable Account or SYS JWT is re-minted without its revocations | Fixed (ready for review) | V1, PR #286 | `internal/pki/tenant.go` `applyStoredRevocations` (a minimal mint carries the database's revocations and fails closed naming the tenant); `jwtauth.go` `sysAccountJWTFromTrust` | `TestLostTenantAccountJWTRebuiltFromDatabase`, `TestLostLegacyAccountJWTRebuiltFromDatabase`, `TestLostSysAccountJWTRebuiltFromDatabase`, `TestLostSysAccountJWTStateTableNotYetMigrated` (`internal/pki/revocation_rebuild_test.go`) |
| I9 | `PushAllAccounts` after a restore pushes without re-syncing revocations | Fixed (ready for review) | V1, PR #286 | `internal/pki/pushall.go` `PushAllAccounts` runs `syncTenantSprouts` for each tenant before it pushes | `TestPushAllAccounts_StaleJWTDoesNotReadmitRevokedSprout` (`internal/pki/pushall_test.go`) |
| I10 | `JobRef{SproutID, JID}` carries no tenant | Fixed (mitigated by design) | F1, PR #227 (the job-status reader refuses a tenant-less lookup) | `internal/saasapi/job_status.go` `JobOutcomes` (refuses an empty tenant, filters and re-checks `tenant_id`); callers pass the batch's tenant | `TestFarmerJobStatusReader`, `TestFarmerJobStatusReader_RefusesEmptyTenant`, `TestGetSproutActionBatch_TwoTenantsSameSproutAndJID` (`internal/saasapi/job_status_test.go`); `TestFleetUpdate_JobStatusGateRollsOutInWaves` (`internal/saasapi/fleet_update_dispatch_test.go`) |
| I11 | Route mTLS uses the general root CA | Accepted | In the review itself (mitigated by the SAN and route-password checks) | `cmd/farmerbus/cluster.go` `routeAuth.Check`, `minRoutePasswordLen` | `TestRouteAuth`, `TestRouteListenerRejectsUnauthenticated` (`cmd/farmerbus/cluster_test.go`) |
| I12 | No body limit on `/v1/enroll`; no directory fsync after the atomic write; a stale comment | Fixed (ready for review) | V1, PR #286 | `internal/api/handlers/enroll.go` `maxEnrollRequestBytes` (64 KiB, 413 on excess); `internal/pki/enrollclient.go` atomic writes sync the directory after the rename; the `pushall.go` comment corrected | `TestEnroll_BodyLimit` (`internal/api/handlers/enroll_test.go`); `TestAtomicWritesSyncTheDirectory` (`internal/pki/atomicwrite_test.go`) |

## Review 2026-10-b

| ID | Finding | State | Fixed in | Where | Pinning tests |
|---|---|---|---|---|---|
| B1 | A staged recipe pulled over `/files/` was cooked with no proof farmer produced it | Fixed (ready for review) | SEC.7a, PR #107 | `internal/cook/stagedfetch.go` with `pki.SproutOpenStagedFromFarmer` | `TestStagedSealed_ForgedPlainEnvelopeIsRefused`, `TestStagedSealed_EnvelopeForAnotherSproutOrTenantIsRefused` (`internal/cook/stagedsealed_test.go`) |
| B2 | A keyless accepted sprout accepted an attacker's box key at enrolment | Fixed (ready for review) | SEC.7b, PR #108 | `internal/pki/enroll.go` (enroll binding, `recordProvenSproutBoxKey`) | `TestEnroll_KeylessSproutRefusesAnAttackerBoxKey`, `TestEnroll_EnrollBindingChecks` (`internal/pki/enroll_test.go`) |
| B3 | A deleted or replaced host's gateway JWT still read `/files/` | Fixed (ready for review) | SEC.7c, PR #104 | `internal/api/middleware.go` `verifySproutGatewayJWT`; `internal/pki/gatewaysubject.go` | `TestFilesRoute_ReacceptedSproutIDRefusesOldHostsGatewayJWT` (`internal/api/gateway_revocation_test.go`); `TestVerifyGatewaySubject_ReplaceRefusesOldHost` (`internal/pki/gatewaysubject_test.go`) |
| B4 | Recipe render cost scaled with the include count | Fixed (ready for review) | S4, PR #266 | `internal/cook/farmercook.go` `cookBudget`, `maxRecipeIncludes` | `TestCookBudget_Shared`, `TestCookIncludeCap`, `TestNoRenderOutsideACookBudget` (`internal/cook/cook_budget_test.go`); UAT acceptance case RB1 (`uat/tests/hardening_test.go`; the over-budget cook's batch item fails with `job_refused`: farmer records a cook it refuses before dispatch in `farmer.job_status`, P29) |
| B5 | M6 carried: the same-second `iat` tie in the fence | Fixed, residual accepted | As M6 | As M6 | As M6 |
| B6 | A forged "no responders" re-runs an action up to the outbox's attempts | Accepted | Owner, PR #97 (BUILD-STATUS "Decisions in force"; P3 walkthrough 3.4 item 5) | `internal/saasapi/sprout_actions.go` (`nats.ErrNoResponders` leaves the item queued) | `TestSproutActionBatch_NoFarmerOrNoBusLeavesItemsQueued` (`internal/saasapi/sprout_actions_test.go`); `TestSweepActionBatches_BackoffAndAttemptLimit` (`internal/saasapi/sweeper_actions_test.go`, the attempt bound) |
| B7 | The built-in `operator` role granted `shell` | Fixed | SH.1, PR #102 | `internal/rbac/config.go` `BuiltinOperatorRole` | `TestOperatorRoleNATSAccess` (`internal/natsapi/middleware_test.go`) |
| B8 | An MSI rc and its final were indistinguishable; zypper's skip was not run | Fixed (ready for review) | T1, PR #273 | `internal/ingredients/selfupdate/pkgmeta.go` `msiFileVersion`; `ErrPrereleaseOnWindows` | `TestVerifyPackageIdentity_MSIFullVersion`, `TestApply_PrereleaseRefusedOnWindows` (`pkgmeta_test.go`); `TestApply_FakeZypperDowngradeSkip` (`zypper_unix_test.go`) |
| B9 | The attacker-set `DispatchedAt` was the only bound on a forged pull | Fixed (ready for review) | SEC.7a, PR #107; SEC.7d, PR #110 | `internal/cook/stagedsync.go` `pullStagedRecipe` (checks the opened envelope; older than the newest handled job is refused) | `TestStagedSealed_ReplayedOldEnvelopeIsRefused` (`internal/cook/stagedsealed_test.go`); `TestSyncStagedRecipe_ClockSkewHandledJobRefused` (`internal/cook/stagedsync_test.go`) |
| B10 | Pointer to the Info notes below | (none) | (none) | (none) | (none) |
| bI1 | The persisted replay guard fails closed for one window; a skew over 5 minutes refuses everything | Accepted (by design) | Review -b itself | `internal/pki/sproutbox.go` `sproutGuard` | `TestSproutGuard_CorruptFileFailsClosed` (`internal/pki/sproutbox_tenant_test.go`) |
| bI2 | Shell keys and the per-session stream hold; keystroke timing is a residual | Accepted (holds; timing residual) | J.5, PR #98 | `internal/natsapi/shell.go` `handleShellOpen`; `internal/payloadbox/stream.go` | `TestHandleShellOpenValidation`, `TestSealedShellBusInjection` (`internal/natsapi/shell_test.go`) |
| bI3 | Confirms H2 fixed | Fixed | As H2 | As H2 | As H2 |
| bI4 | The job store had no tenant segment in its keys | Fixed (ready for review) | FIX.2, PR #111 | `internal/jobs/store.go` `jobKey` (`jobs/<tenant>/<sprout>/<jid>`) | `TestJobKey_RefusesHostileSegments`, `TestTwoTenants_SameSproutAndJID_WriteListReadDelete` (`internal/jobs/tenant_test.go`) |
| bI5 | Confirms M7 fixed | Fixed | As M7 | As M7 | As M7 |
| bI6 | URL redaction covers http(s) URLs; a scheme-less URL in a message would pass | Fixed; scheme-less residual accepted in the review | SEC.5, PR #86 | `internal/ingredients/selfupdate/download.go` `reURLQuery`, `redactedError` | `TestRedactedError`, `TestApply_RedirectURLsNeverReachTheError` (`internal/ingredients/selfupdate/pkgmeta_test.go`) |

## P11: carry-over follow-ups from PRs #62 to #113

The list is the archive's Open item 10
([`archive/BUILD-STATUS-2026-10-09.md`](archive/BUILD-STATUS-2026-10-09.md),
"Leftovers and follow-ups from PR #62 to #113"). The build plan has no
separate list; it only cites that item. Each follow-up was checked on `main`.
**Done**: on `main` already, with where it is. **Done (V3)**: built in this
unit. **Decided**: no code change. The verdict follows the owner decisions
and the code on `main`, and names where the reason is recorded. **Out of
scope**: by the owner decision in `docs/briefs/V-leftovers.md` (the web UI
submodule), or the item needs a real release, the Azure run or another unit.

| # | Area | Follow-up | Verdict | Where, or why |
|---|---|---|---|---|
| 1 | Release | Re-enable `release.yml`'s tag trigger | Done | `.github/workflows/release.yml` `on: push: tags: ["v*"]` |
| 2 | Release | Commit the GPG public key | Done | `gpg-public-key.asc` (P22, PR #226); release gate `packaging/test/keyring_test.go` (T1) |
| 3 | Release | The rest of the first release checklist; chart publishing | Out of scope | Unit V2 (P10) and real releases (`docs/RELEASING.md`) |
| 4 | Release | nfpm packages carry a `+git` version suffix | Decided | The sprout maps it back to semver (SEC.5, `internal/ingredients/selfupdate/pkgmeta.go`) |
| 5 | Release | Check each catalog row against the tag's signed `checksums.txt` | Done | P22: the registration carries `checksums.txt` and its signature (`internal/saasapi/fleet_releases.go`), and the sprout verifies them against its keyring |
| 6 | Release | OIDC-to-Rekor, image builds, `sha256sum --check` and MSI reproducibility untested | Out of scope | Needs a real release (V2 and the release checklist) |
| 7 | Release | `RELEASING.md` step 4 calls the `go-licenses` save a known failure | Done (V3) | `docs/RELEASING.md` step 4: the workflow must be green (it passes since LIC.1) |
| 8 | Enrolment | Pre-CL.1 sprouts keep the unused `fleetsigningkeys` grant | Done | Farmer re-mints a JWT whose permissions differ from `pki.SproutPermissions`; `internal/pki/sproutjwt_isolation_integration_test.go` |
| 9 | Enrolment | A sprout uses a changed JWT only after a restart | Done | T3, PR #275: `cmd/sprout` `heartbeatGate`, `pki.SproutBus.ReloadUserJWT` |
| 10 | Enrolment | Re-sync every tenant's revocations at farmer start | Done | V1, PR #286, finding I9: `PushAllAccounts`, which runs on every bus connect including farmer's start, runs `syncNatsAuth` for the legacy tenant and `syncTenantSprouts` for each live tenant before pushing |
| 11 | Deleted sprouts | User JWTs have no `exp`, so the revoked list only grows | Decided | Revocation is carried in each Account JWT (H1, SEC.3a). Rows of deleted sprouts are erased with the tenant (S6) |
| 12 | Deleted sprouts | A deleted sprout's stored JWT stays behind | Done (V3) | `internal/pki` `DeleteNKey` now also deletes the sprout's stored User JWT row and its object (`forgetSproutUserJWT`) |
| 13 | Deleted sprouts | Envoy can't see revocation; a retired host's gateway JWT costs farmer a lookup | Decided | Accepted in `docs/security-review-pack.md` 3.5 item 2 (P3 walkthrough, 2026-10-17); farmer refuses it (SEC.7c) |
| 14 | Sealed | A keyless accepted sprout is closed; nothing deletes it or regenerates its NKey | Decided | "Sealed only, no downgrade" (BUILD-STATUS "Decisions in force"); `imas keys delete` and a fresh enrolment |
| 15 | Sealed | A keyless sprout gets no staged copy, so a pull can't catch it up | Decided | Same decision |
| 16 | Sealed | A copy staged before a tenant key rotation is not caught up (PR #107 question 1) | Decided | No previous pin is kept, by design (`docs/design/imas-payload-encryption-design.md`). The next dispatch reaches the sprout |
| 17 | Sealed | A copy staged before a box key rotation is pulled after the grace | Decided | Bounded by `sproutboxkeyprevgrace` (`config.DefaultSproutBoxKeyPrevGrace`), by design |
| 18 | Sealed | The `stagedrecipeclockskew` window lets an older captured job run | Decided | Accepted cost in SEC.7d (PR #110), capped at 5 minutes (`config.MaxStagedRecipeClockSkew`) |
| 19 | Sealed | A staged copy's size and key are visible to `/files/` readers | Decided | Accepted residual, `docs/security-review-pack.md` 3.4 (P3 walkthrough, 2026-10-17) |
| 20 | Sealed | The join event is plaintext | Decided | P6 owner decision, 2026-10-18 |
| 21 | Sealed | `jobs.cancel` is plaintext and nothing on the sprout acts on it | Decided | P6 owner decision, 2026-10-18 (cancel stays an accepted residual) |
| 22 | Sealed | An older CLI prints `invalid message` for a result with an error | Decided | An old binary can't be changed; a current CLI decodes it (PR #118) |
| 23 | Sealed | `imas cook` keeps exit status 0 when the cook failed | Done (V3) | `cmd/imas/cmd/cook.go`: exits 1 when a step failed, the wait timed out, or a target never completed |
| 24 | Sealed | Should a remote failure exit 2 rather than 1? | Decided | 1, as on `main` for `imas cmd run`; `imas cook` matches it |
| 25 | Sealed | `PingPong.Error` and `Inline.Error` print as `{}` | Done | PR #122 (`internal/api/types/wireerror.go`) |
| 26 | Sealed | A multi-sprout CLI cook only logs a keyless sprout's refusal | Decided | The sprout never completes, so the CLI reports it as not completed, and since V3 `imas cook` exits 1 for it (row 23) |
| 27 | Sealed | `cmd.RegisterNatsConn` and its unused connection | Done (V3) | Removed from `internal/ingredients/cmd` and `internal/ingredients/test` and their calls in `cmd/sprout/main.go` |
| 28 | Sealed | The routeless `HTestPing` handler | Done (V3) | `internal/api/handlers/ingredients/` deleted (no importer) |
| 29 | Sealed | The orchestration doc describes the removed plaintext fallback | Done (V3) | `docs/design/imas-sprout-orchestration.md`, "As built: cook's wire format" |
| 30 | Sealed | The exported test seam `pki.UseInMemoryJoinToken` | Done (V3) | Panics outside a test binary (`testing.Testing()`) |
| 31 | Sealed | Should the proof of possession also carry the binding ID? | Decided | No: the enrol binding was confirmed sound in the P3 walkthrough 3.5 (2026-10-17) |
| 32 | Sealed | Should an out-of-range `stagedrecipeclockskew` stop the sprout? | Decided | No: it logs and uses the default, like every bounded sprout setting on `main` (`internal/config`) |
| 33 | Job store | A lookup by JID alone lists the tenant's whole prefix | Out of scope | Scale work, BUILD-STATUS P23 |
| 34 | Job store | The reaper lists the whole bucket hourly on every replica | Done | `internal/jobs/expiry.go` `reapLeased` runs under one cluster-wide lease |
| 35 | Job store | Old-layout objects are never read or swept | Decided | No deployment wrote the old layout (`docs/security-review-2026-10-b.md` I4); `TestOldLayoutNotRead` |
| 36 | Facts | `props.static` can set reserved fact names | Done (V3) | `cmd/farmer` `staticPropsWithoutFacts` drops reserved names, and names outside `props.ValidName` (which PXC's collation could fold onto a reserved row), before loading them, with an error log; at start `props.DropStaticProps` removes any such row an older farmer stored (`TestStaticPropsWithoutFacts`, `TestStaticPropNameRefused`, `TestDropStaticProps`) |
| 37 | Facts | `hostname` in a recipe is the reported fact, then the sprout ID | Decided | By design, SEC.4 (`internal/cook/farmercook.go`, `facts.HostnamePropTTL`) |
| 38 | Facts | `props.GetHostnameFuncForTenant` has no caller | Done (V3) | Deleted with `GetHostnameFunc`: both returned farmer's own hostname |
| 39 | Facts, REC.1 | A deprovisioned tenant's `recipes/` and `recipe-audit/` are not deleted | Done | S6, PR #268: the purge deletes `tenants/<id>/` (`internal/tenantpurge`); on a deployed stack: UAT acceptance case E1 |
| 40 | Facts | The render budget is per render, not per cook | Done | S4, PR #266 (`cookBudget`) |
| 41 | REC.1 | Audit records are bucket objects, not a `saas` table | Decided | Retention (U4) and erasure (S6) are built on the object form; `docs/retention.md` |
| 42 | REC.1 | Audit retention and PR #90's defaults questions | Done | U4, PR #283: `farmer.retention.recipeAuditDays` (365 days), `docs/retention.md`; on a deployed stack, with short settings: UAT acceptance case D1 |
| 43 | REC.1 | §1.5's `cook` action has no recipe role check | Decided | The actions route also runs `cmd.run`, so a recipe role on `cook` alone would narrow nothing (recorded in `docs/design/imas-machine-manager-api-design.md`) |
| 44 | REC.1 | `DELETE` with `If-Match` is a check then a delete; validation renders with empty props | Decided | S3 has no conditional delete; the cook-time budget is the enforcement (documented in the API design, "Concurrency" and "Validation") |
| 45 | FIX.3 | The AWS read probe vs a key that can't list; PR #112's questions | Decided | The probe and its limit are documented in FIX.3; the chart's rule and the required bootstrap admin stay as on `main` |
| 46 | OPS.1 | `saasapi.pdb.maxUnavailable` of 0 or at least `replicaCount` is not refused | Done (V3) | `deploy/helm/farmer/templates/saasapi-pdb.yaml` refuses both |
| 47 | OpenBao | The credential publisher has no `extraEnv` | Done (V3) | `credentialPublisher.extraEnv` on the Job and the CronJob |
| 48 | OpenBao | No sprout-side namespace; the `bao` CLI steps set none; no test against a namespaced server | Decided | Not supported, and now documented (`docs/INSTALL.md` "Sprouts", `deploy/helm/farmer/README.md` "Namespaces") |
| 49 | Web UI | `imas serve`'s add-user form must send `boxpub` | Out of scope | Owner decision: the `grlx-web-ui` submodule is empty on `main` |
| 50 | CLI | After a tenant key rotation the CLI re-pins `tenantboxpub` by hand | Decided | The documented procedure (`docs/INSTALL.md`, "The imas CLI") |
| 51 | Tests | The JWT-detector helpers are copied into two packages | Done (V3) | One shared test helper package, `internal/payloadbox/sealedwiretest` |
| 52 | Tests | In-memory test databases keyed on `t.Name()` break under `-count` | Done (V3) | Every `mode=memory` DSN carries a per-package counter, as `internal/pki` already did |
| 53 | Codes | Move `self_update_disabled` and the other farmer-only codes into `internal/controlplane` | Done (V3) | `controlplane.ErrorSelfUpdateDisabled`, `ErrorRolloutWindowClosed`, `ErrorFarmerBusy`, `ErrorSproutReenrollRequired`; pinned by `TestSproutActionErrorCodeValues` |

## P17: tests that pinned the old behaviour, and test gaps

BUILD-STATUS P17 listed tests that would pass while a problem existed, and
tests that pinned the behaviour a fix would change. After the S, T and U
batches:

| Item | Then | Now |
|---|---|---|
| L9 | `internal/natsapi/sprout_action_test.go` and `internal/saasapi/sprout_actions_test.go` passed output through | Changed (U1): `TestSproutAction_CmdRunThroughRealHandler` requires no output in the reply. V3 adds `TestCmdRunResultCarriesNoOutput`, because the saasapi side held only through the type |
| L12 | `internal/api/handlers/pki_test.go` filed an unproven NKey | Changed (T6): `TestPutNKey_RefusesWithoutProofOfPossession` |
| L20 | `rotation_test.go` dropped the token by hand | Changed (T5): `TestCertRotationWhileRunning` fails unless the reload drops it |
| L22 | `TestTenantKeyContinuity_SkipsDeletedVersions` | Changed (U1): `TestTenantKeyContinuity_GapStopsTheWalk` and `_DeletingTheSeveringVersionKeepsTheCut` |
| I1 | `TestCheckDSN` accepts a non-UTC `loc` with a warning | Changed (V1, PR #286): `TestCheckDSN` requires the refusal; `TestOpenDBRefusesNonUTCLoc` and `TestRequireUTC` pin farmer's side |
| I2 | Tests accepted `http://` | Changed (T5): they set `*_OPENBAO_ALLOW_INSECURE=true`, and `TestInsecureAddrRefused` pins the refusal |
| Error codes | `TestItemErrorCodesDocumented` iterated only the message map | Closed (T2): it derives the stored codes from the source |
| B4 | Nothing tested `maxRecipeIncludes` | Closed (S4): `internal/cook/cook_budget_test.go` |
| I5 | `-tags no_self_update` read by no file | Closed (T1). V3 adds `TestNoSelfUpdateBuildTag` and `TestSproutLinksSelfUpdate` |
| L5 | `packaging/test` checked the keyring's presence only | Closed (T1): `TestPackagedKeyring`, `TestReleaseChecksums` |
| P5 | No test for farmer's redial after the NATS client gives up | Closed (T2): `TestTenantRedialAfterNATSClientGivesUp` (`cmd/farmer/tenantredial_test.go`) |
| P12 | No heartbeat race or Valkey Cluster test | Closed (T3): `TestPresence_ReconnectRace_BothOrders` (`internal/heartbeat/presence_race_test.go`, a 3-shard cluster in CI) |
| P4 | Other re-signs could tie on `iat` | Closed (T2): `TestEveryAccountResignWaitsPastIssuedAt`, `TestEveryResignAdvancesIat` |
| L13 | The test turned Trace and Debug off itself | Closed (T6): `TestBusDefaultLogLevelLogsNoPayload`. V3 adds `TestBaseNatsOptionsNoTraceOrDebug` for the bus defaults |

Gaps left: none that a test can close. The only findings without a pinning
test are documentation changes (L7, I3).
