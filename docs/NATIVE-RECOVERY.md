# Native SCRAM backup, restore and effect reconciliation

The integrated recovery test exercises the actual native role services before
and after a database restore. Its scope is a new owned PostgreSQL 18 cluster,
synthetic credentials and one protected local file. It uses the maintained
service policies, SDK, independent validator, file adapter and observer. It
does not modify their implementations or the original recovery suite.

Run from the repository root using the existing checked Python/PostgreSQL/macOS
environment:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_native_recovery.py' -v
```

The test performs these actual operations:

1. Install into a fresh private cluster, then use `secure_admin` to assign a
   generated administrator password and require SCRAM for every local login.
   TCP is rejected. All eight native role endpoints authenticate as their own
   logins; wrong-password attempts receive actual password-authentication
   failures.
2. Register the trusted input and exact report bytes, activate the contract,
   and run the real independent validator through the native verifier identity.
   A native adapter dispatches the accepted bytes and records its attempted
   result. The caller then deliberately discards that real completed response.
   This is a controlled caller-reply loss, not a simulated power failure or a
   manually edited effect state. The database preserves `attempted` while the
   caller's outcome is unknown.
3. Verify and retain a caller-held audit checkpoint outside PostgreSQL. Run an
   actual custom-format `pg_dump`. A wrong-password dump control refuses; the
   successful dump uses only the newly generated administrator password in a
   clean subprocess environment. No password appears in arguments, DSNs,
   retained diagnostics or receipt files, and no ambient authentication files
   are used.
4. Stop and restart only the owned PostgreSQL runtime, preserving its SCRAM
   authentication state. Restore the dump with `pg_restore` into a newly
   created database in that same cluster. Create new private per-role configs
   pointing the native services at the restored database and the same protected
   destination.
5. Authenticate every restored native role, verify continuity from the
   caller-held audit checkpoint, and compare the exact binding, checks,
   historical acceptance, attempted effect and spent verification/effect
   budgets. The restore does not recreate acceptance or refund consumption.
6. Attempt redispatch through the restored native adapter. It must refuse with
   `RECONCILIATION_REQUIRED`. Then let the separately confined native observer
   read the existing file and record completion. The file's inode, size,
   modification/change timestamps and digest stay unchanged; the report history
   contains one dispatch, one attempted report and one independent observation.
   The original source database remains `attempted`, demonstrating that the
   observer used the restored database.
7. Attempt actual destination writes under the restored worker and observer
   profiles, and direct protected-table writes/owner-role assumption with the
   restored worker credential. The filesystem probes require actual permission
   denial with unchanged output. The SQL probe catches only PostgreSQL's
   `insufficient_privilege`, not an arbitrary transport failure.

The private retained evidence directory contains the archive, pre/post effect
and budget snapshots, caller/restored/final checkpoints, tool return codes and
diagnostics, and a completion/failure receipt. The test checks its real statement
log for generated passwords and SCRAM verifiers. Runtime credentials are revoked
and the owned cluster is stopped during cleanup. The per-role configuration
files remain private inside that owned runtime for diagnosis; they contain
only synthetic credentials whose runtime roles are revoked during cleanup.
The administrator's generated password is not written to a configuration file.

This qualifies the named **same-cluster** recovery path. PostgreSQL roles and
their password records remain in the existing owned cluster; they are not
included in a global role dump. Cross-cluster identity/issuer recovery, live
vault recovery, lost external artifacts and administrator-compromise resistance
remain outside this test. The retained file is an external consequence preserved
across the database restore, not an artifact reconstructed by `pg_restore`.

The supervisor/operator and other unsandboxed processes sharing its OS identity
remain trusted. An audit checkpoint held by the test outside the database proves
continuity to that checkpoint in this controlled run; it does not establish an
independent production checkpoint store. See [native deployment scope](NATIVE-DEPLOYMENT.md)
and [general operations](OPERATIONS.md) for the surrounding boundaries.
