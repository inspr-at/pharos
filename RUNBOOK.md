# Pharos runbook

Beacon credentials and store recovery. Commands use `https://pharos.example` and
the host name `new-host`; replace both with yours, and keep real values out of
this repository.

Every report needs a bearer token whose SHA-256 matches the host's `token_hash`
in the store. `POST /register` is the one way to issue a token, and it stays
switched off except during the actions below.

The store (`PHAROS_DB`, for example `/data/pharos.json`) is the only copy of the
token hashes. Pharos writes it atomically, so a plain file copy is a consistent
backup. It contains no raw tokens, but treat it as sensitive anyway.

## Switch registration on and off

Switching on needs both settings. A switch without a token file refuses startup,
and so does `PHAROS_REGISTRATION_TOKEN` set directly.

1. Create a one-time token file that only the pharosd user can read. The image
   runs as UID 10001:

   ```bash
   umask 077
   head -c 32 /dev/urandom | base64 >registration-token
   sudo chown 10001 registration-token
   ```

2. Check that user can read it, using the image you run. This must print
   `readable`, because a file pharosd cannot read refuses startup:

   ```bash
   docker run --rm --user 10001 --entrypoint /bin/sh \
     -v "$PWD/registration-token:/registration-token:ro" IMAGE \
     -c 'test -r /registration-token && echo readable'
   ```

3. Mount it read-only into the container, then set:

   ```text
   PHAROS_ALLOW_LOCAL_REGISTER=true
   PHAROS_REGISTRATION_TOKEN_FILE=/run/secrets/pharos-registration-token
   ```

4. Recreate the container and do the work.
5. Remove both settings and the mount, recreate the container and delete the file.
6. Confirm `POST /register` answers `410`.

Do not leave registration on. Anyone holding this token can replace the token of
any host.

## Add a host

With registration on, register the host and write the response to a private file.
The token reaches curl on stdin, which keeps it out of the process list:

```bash
umask 077
printf 'Authorization: Bearer %s\n' "$(sudo cat registration-token)" |
  curl --fail-with-body -sS -o new-host.json -H @- \
    -H 'Content-Type: application/json' \
    -d '{"schema":"inspr.pharos.host-registration.v1","version":1,
         "name":"new-host","role":"server","is_nix":true,
         "heartbeat_interval_secs":60}' \
    https://pharos.example/register
```

The `token` in `new-host.json` is shown this once. Move it into the host's secret
store as `PHAROS_TOKEN`, delete the file, start the beacon and switch registration
off.

Verify after login: the host appears at `/hosts.json` with `"liveness": "live"`.

## Rotate a token

A host with no stored hash gets 401: Pharos only checks tokens against its store.
A store from a server that checked tokens somewhere else has no hash for those
hosts, so rotate each of them before relying on its reports.

Run the same `POST /register` with the existing host name.

- The old token stops working immediately, so the beacon answers `401` until it
  has the new one.
- Report history stays.

Install the new token, restart the beacon, confirm `last_seen` moves and switch
registration off.

## Recover a lost store

pharosd starts with an empty store if the file is gone, and every beacon then gets
`401` with `report rejected: invalid bearer token` in the log.

### From a backup

A backup brings back the token hashes it holds. A token rotated after the backup,
even one rotated because it leaked, is accepted again as soon as pharosd starts on
that file. Clear those hosts first so the old token never works.

1. Stop pharosd.
2. Clear the hash of every host whose token changed after the backup. A host
   without a hash keeps its history and answers `401` to any token:

   ```bash
   umask 077
   jq --argjson hosts '["new-host"]' \
     'map(if (.name | IN($hosts[])) then del(.token_hash) else . end)' \
     backup.json >pharos.json
   ```

   If you cannot tell which tokens changed, clear them all with
   `jq 'map(del(.token_hash))' backup.json >pharos.json`, and rotate every host.

3. Put `pharos.json` in place as the store file, owned by the pharosd user.
4. Start pharosd. Beacons with an unchanged token report again at their next
   heartbeat.
5. Switch registration on, rotate each cleared host, and add any host created after
   the backup. Then switch registration off.

### Without a backup

Switch registration on, follow **Add a host** for every host, including the new
token on each host, and switch registration off. Report history starts again from
empty.

## Drill record

Drilled against throwaway containers, each run with the hardening production uses:
read-only root, all capabilities dropped, no new privileges, non-root user, process
and memory limits, and a small `/tmp`. The drill runs every action above and checks
the answers.

| Date       | Image                  | Result                                            |
| ---------- | ---------------------- | ------------------------------------------------- |
| 2026-10-31 | `6bae993d3026` (arm64) | 48 of 48 checks passed; add, rotate, recover both |
