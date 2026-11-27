// The core's C ABI, loaded through bun:ffi as the desktop's Bun loads it.
// DUVET_E2E_FFI names the built library (`cargo build -p duvet-e2e-ffi --release`).
import { describe, expect, test } from "bun:test";
import { CString, dlopen, FFIType, suffix } from "bun:ffi";
import { randomBytes, randomUUID } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

// duvet_e2e_ffi.dll on Windows, libduvet_e2e_ffi.dylib on macOS, libduvet_e2e_ffi.so elsewhere.
const name = `${process.platform === "win32" ? "" : "lib"}duvet_e2e_ffi.${suffix}`;
const library = process.env.DUVET_E2E_FFI ?? join(import.meta.dir, "../../target/release", name);

const { symbols: lib } = dlopen(library, {
  duvet_e2e_open: { args: [FFIType.ptr], returns: FFIType.ptr },
  duvet_e2e_handle: { args: [FFIType.u64, FFIType.ptr], returns: FFIType.ptr },
  duvet_e2e_close: { args: [FFIType.u64], returns: FFIType.void },
  duvet_e2e_destroy: { args: [FFIType.ptr], returns: FFIType.ptr },
  duvet_e2e_free: { args: [FFIType.ptr], returns: FFIType.void },
  duvet_e2e_version: { args: [], returns: FFIType.cstring },
});

/** A NUL-terminated UTF-8 string, as the library reads one. */
const cstring = (text: string) => Buffer.from(`${text}\0`, "utf8");

/** A reply the library allocated: read, handed back to it, parsed. */
function take(pointer: unknown) {
  expect(pointer).toBeTruthy();
  const json = new CString(pointer as never).toString();
  lib.duvet_e2e_free(pointer as never);
  return JSON.parse(json);
}

const open = (config: object | string) =>
  take(lib.duvet_e2e_open(cstring(typeof config === "string" ? config : JSON.stringify(config))));
const handle = (core: number, command: string | Buffer) =>
  take(lib.duvet_e2e_handle(BigInt(core), typeof command === "string" ? cstring(command) : command));
const close = (core: number) => lib.duvet_e2e_close(BigInt(core));
const destroy = (config: object) => take(lib.duvet_e2e_destroy(cstring(JSON.stringify(config))));

const database = () => join(mkdtempSync(join(tmpdir(), "duvet-e2e-")), "core.db");
const dbKey = () => randomBytes(32).toString("base64");
const status = '{"cmd":"status"}';
const createDevice = (device: string) =>
  JSON.stringify({ cmd: "create_device", user_id: randomUUID(), device_id: device });
/** A keyring entry of this run's own. */
const keyring = () => ({ service: "duvet-e2e-test", account: `core-${randomBytes(8).toString("hex")}` });

// Where a keyring config's key lands somewhere a test may write: a file, on Linux with no session
// bus (CI's container); Windows' Credential Manager, on windows.yml's runner. zbus finds the bus
// at $XDG_RUNTIME_DIR/bus too, where it would be a developer's own keyring.
const busSocket = join(process.env.XDG_RUNTIME_DIR ?? `/run/user/${process.getuid?.()}`, "bus");
const keyFile = process.platform === "linux" && !process.env.DBUS_SESSION_BUS_ADDRESS && !existsSync(busSocket);
const credentialManager = process.platform === "win32";

describe("the C ABI", () => {
  test("status replies protocol 1", () => {
    const core = open({ path: database(), db_key: dbKey() }).ok.handle;
    const reply = handle(core, status).ok;
    expect(reply.protocol).toBe(1);
    expect(reply.key_storage).toBe("provided");
    expect(reply.version).toBe(lib.duvet_e2e_version().toString());
    close(core);
  });

  test("opening the same database twice is locked", () => {
    const config = { path: database(), db_key: dbKey() };
    const first = open(config).ok.handle;
    expect(open(config).error.code).toBe("locked");

    close(first);
    const again = open(config).ok.handle;
    expect(handle(again, status).ok.protocol).toBe(1);
    close(again);
  });

  test("broken JSON is bad_command, and the process goes on", () => {
    const path = database();
    expect(open("{").error.code).toBe("bad_command");
    expect(open({ path }).error.code).toBe("bad_command");
    expect(open({ path, db_key: "AAAA" }).error).toMatchObject({ code: "bad_command", field: "db_key" });

    const core = open({ path, db_key: dbKey() }).ok.handle;
    expect(handle(core, "{").error.code).toBe("bad_command");
    expect(handle(core, Buffer.from([0x7b, 0xff, 0x00])).error.code).toBe("bad_command");
    expect(handle(core, status).ok.protocol).toBe(1);
    close(core);
  });

  test("a closed or unknown handle is not_found", () => {
    const core = open({ path: database(), db_key: dbKey() }).ok.handle;
    close(core);
    expect(handle(core, status).error).toMatchObject({ code: "not_found", what: "handle" });
    expect(handle(0, status).error.code).toBe("not_found");
    close(core);
  });

  // Where no session bus runs, as in CI's container, Linux has no Secret Service. Windows and macOS
  // keep the key in their own keyring, never in a file.
  test.skipIf(!keyFile)(
    "without Secret Service the key goes to a file only its user reads",
    () => {
      const path = database();
      const config = { path, keyring: { service: "duvet-e2e-test", account: "core" } };
      const core = open(config).ok.handle;
      expect(handle(core, status).ok.key_storage).toBe("file");
      close(core);

      expect(statSync(`${path}.key`).mode & 0o777).toBe(0o600);
      expect(readFileSync(`${path}.key`).length).toBe(32);
      expect(open({ path, db_key: dbKey() }).error.code).toBe("bad_key");

      const again = open(config).ok.handle;
      expect(handle(again, status).ok.key_storage).toBe("file");
      close(again);
    },
  );

  test.skipIf(!keyFile && !credentialManager)("destroy leaves nothing to open", () => {
    const path = database();
    const config = { path, keyring: keyring() };
    const device = randomUUID();
    const core = open(config).ok.handle;
    expect(handle(core, createDevice(device)).ok).toBeDefined();

    // While a handle has it open, nothing goes.
    expect(destroy(config).error.code).toBe("locked");
    close(core);
    const kept = open(config).ok.handle;
    expect(handle(kept, status).ok.device_id).toBe(device);
    close(kept);

    const key = keyFile ? readFileSync(`${path}.key`) : null;
    expect(destroy(config)).toEqual({ ok: {} });
    for (const file of [path, `${path}.key`]) expect(existsSync(file)).toBe(false);
    // The locks stay, empty: an open may be waiting for one or racing for the other.
    for (const lock of [`${path}.lock`, `${path}.key.lock`]) expect(statSync(lock).size).toBe(0);

    // What opens there now is a new database, with a key of its own.
    const fresh = open(config).ok.handle;
    expect(handle(fresh, status).ok.device_id).toBeUndefined();
    close(fresh);
    if (key) expect(readFileSync(`${path}.key`).equals(key)).toBe(false);
    expect(destroy(config)).toEqual({ ok: {} });
  });

  // A group command through the same JSON: a device founds a DM alone, with no key package of the
  // other member's, types a message there and forgets it, which leaves the message stale (groups.rs'
  // a_lone_device_forgets_the_group_it_founded).
  test("forget_group answers the group's members, and the group is gone", () => {
    const core = open({ path: database(), db_key: dbKey() }).ok.handle;
    const [user, other, conversation] = [randomUUID(), randomUUID(), randomUUID()];
    const run = (command: object) => handle(core, JSON.stringify(command));
    expect(run({ cmd: "create_device", user_id: user, device_id: randomUUID() }).ok).toBeDefined();
    expect(run({ cmd: "create_identity" }).ok).toBeDefined();
    const external_sender = randomBytes(32).toString("base64");
    const members = [user, other];
    const create = { cmd: "create_group", conversation_id: conversation, kind: "dm", members, external_sender };
    expect(run(create).ok.generation).toBe(0);
    expect(run({ cmd: "commit_result", conversation_id: conversation, accepted: true, seq: 1 }).ok.epoch).toBe(1);
    const typed = { cmd: "encrypt", conversation_id: conversation, nonce: "typed", envelope: { text: "hello" } };
    expect(run(typed).ok.epoch).toBe(1);

    const forget = { cmd: "forget_group", conversation_id: conversation };
    expect(run(forget)).toEqual({ ok: { expected: { members, exact: true } } });
    expect(run(typed).error).toMatchObject({ code: "rule_violation", rule: "stale_message" });
    const none = { code: "not_found", what: "group" };
    expect(run({ cmd: "group", conversation_id: conversation }).error).toMatchObject(none);
    expect(run(forget).error).toMatchObject(none);
    // Founded again at generation 0, the group ID the forgotten one had.
    expect(run({ ...create, expected: { members } }).ok.generation).toBe(0);
    close(core);
  });

  // Windows' Credential Manager, the desktop's keyring: windows.yml runs these on a release's DLL.
  test.skipIf(!credentialManager)("the keyring keeps the key", () => {
    const path = database();
    const config = { path, keyring: keyring() };
    const device = randomUUID();
    const core = open(config).ok.handle;
    expect(handle(core, status).ok.key_storage).toBe("keyring");
    expect(handle(core, createDevice(device)).ok).toBeDefined();
    close(core);
    expect(existsSync(`${path}.key`)).toBe(false);

    // The next open takes the key from the credential: the same database, with its device.
    const again = open(config).ok.handle;
    expect(handle(again, status).ok).toMatchObject({ key_storage: "keyring", device_id: device });
    close(again);
    expect(destroy(config)).toEqual({ ok: {} });
  });

  test.skipIf(!credentialManager)("destroy removes the credential", () => {
    const path = database();
    const config = { path, keyring: keyring() };
    close(open(config).ok.handle);
    // A copy of the database, under the same entry: only the credential's key opens it.
    const copy = { path: join(dirname(path), "copy.db"), keyring: config.keyring };
    copyFileSync(path, copy.path);
    close(open(copy).ok.handle);

    expect(destroy(config)).toEqual({ ok: {} });
    // The credential went with its database: nothing opens the copy now.
    expect(open(copy).error.code).toBe("bad_key");
    expect(destroy(copy)).toEqual({ ok: {} });
  });
});
