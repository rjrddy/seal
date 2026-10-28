const $ = (id) => document.getElementById(id),
  encoder = new TextEncoder();
let state = null,
  kind = "inclusion",
  bundle = null,
  busy = false;
const canonicalEntry = (e) =>
  JSON.stringify({
    seq: e.seq,
    previous: e.previous,
    payload: e.payload,
    hash: e.hash,
  });
function require(ok, message) {
  if (!ok) throw Error(message);
}
function fields(value, names) {
  require(value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("|") ===
      names.sort().join("|"), "Unexpected proof fields");
}
function hex(text, size) {
  require(typeof text === "string" &&
    /^(?:[0-9a-f]{2})*$/.test(text), "Noncanonical hex");
  const bytes = Uint8Array.from(text.match(/../g) || [], (p) =>
    parseInt(p, 16),
  );
  require(size === undefined || bytes.length === size, "Invalid byte length");
  return bytes;
}
const toHex = (bytes) =>
  Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
function join(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let at = 0;
  for (const a of arrays) {
    out.set(a, at);
    at += a.length;
  }
  return out;
}
function u64(n) {
  require(Number.isSafeInteger(n) &&
    n >= 0, "Browser verifier requires safe integer sizes");
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}
async function sha(...parts) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", join(...parts)));
}
const node = (a, b) => sha(new Uint8Array([1]), a, b),
  same = (a, b) => toHex(a) === toHex(b);
async function checkpoint(c, key, id, steps) {
  fields(c, ["version", "log_id", "size", "root", "chain_head", "signature"]);
  require(c.version === 1, "Checkpoint version rejected");
  require(c.log_id === id, "Log identity mismatch");
  const message = join(
    encoder.encode("SEAL-CHECKPOINT-v1\0"),
    hex(c.log_id, 32),
    u64(c.size),
    hex(c.root, 32),
    hex(c.chain_head, 32),
  );
  if (c.size === 0)
    require(same(hex(c.root, 32), await sha()) &&
      c.chain_head === "00".repeat(32), "Invalid empty checkpoint");
  const imported = await crypto.subtle.importKey(
    "raw",
    hex(key, 32),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  require(await crypto.subtle.verify(
    "Ed25519",
    imported,
    hex(c.signature, 64),
    message,
  ), "Ed25519 signature rejected");
  steps.push(`Ed25519 signature · tree size ${c.size}`);
}
async function browserVerify(proof, key, id) {
  const steps = [];
  try {
    hex(id, 32);
    hex(key, 32);
    if (kind === "inclusion") {
      fields(proof, ["entry", "checkpoint", "path"]);
      await checkpoint(proof.checkpoint, key, id, steps);
      const e = proof.entry,
        c = proof.checkpoint;
      fields(e, ["seq", "previous", "payload", "hash"]);
      const payload = hex(e.payload);
      require(payload.length <= 16384, "Payload limit");
      const hash = await sha(
        encoder.encode("SEAL-ENTRY-v1\0"),
        u64(e.seq),
        hex(e.previous, 32),
        u64(payload.length),
        payload,
      );
      require(same(hash, hex(e.hash, 32)), "Entry hash mismatch");
      steps.push("Entry hash and canonical byte encoding");
      require(Array.isArray(proof.path) &&
        proof.path.length <= 64 &&
        e.seq < c.size &&
        c.size > 0, "Inclusion bounds rejected");
      let f = BigInt(e.seq),
        s = BigInt(c.size) - 1n,
        acc = await sha(new Uint8Array([0]), encoder.encode(canonicalEntry(e)));
      for (const value of proof.path) {
        require(s > 0n, "Extra inclusion node");
        const sibling = hex(value, 32);
        if ((f & 1n) === 1n || f === s) {
          acc = await node(sibling, acc);
          while (f !== 0n && (f & 1n) === 0n) {
            f >>= 1n;
            s >>= 1n;
          }
        } else acc = await node(acc, sibling);
        f >>= 1n;
        s >>= 1n;
      }
      require(s === 0n &&
        same(acc, hex(c.root, 32)), "Merkle inclusion root mismatch");
      steps.push(`Merkle inclusion path · ${proof.path.length} nodes`);
    } else {
      fields(proof, ["old", "new", "path"]);
      await checkpoint(proof.old, key, id, steps);
      await checkpoint(proof.new, key, id, steps);
      const a = proof.old,
        b = proof.new,
        p = proof.path;
      require(a.size <= b.size &&
        Array.isArray(p) &&
        p.length <= 65, "Consistency bounds rejected");
      if (a.size === 0) {
        require(p.length === 0 &&
          same(hex(a.root, 32), await sha()), "Invalid empty prefix");
      } else if (a.size === b.size) {
        require(a.root === b.root &&
          a.chain_head === b.chain_head &&
          p.length === 0, "Equal-size fork");
      } else {
        require(p.length > 0, "Missing consistency path");
        let f = BigInt(a.size) - 1n,
          s = BigInt(b.size) - 1n;
        while ((f & 1n) === 1n) {
          f >>= 1n;
          s >>= 1n;
        }
        const power = (BigInt(a.size) & (BigInt(a.size) - 1n)) === 0n;
        let fr = hex(power ? a.root : p[0], 32),
          sr = fr;
        for (const value of p.slice(power ? 0 : 1)) {
          require(s > 0n, "Extra consistency node");
          const h = hex(value, 32);
          if ((f & 1n) === 1n || f === s) {
            fr = await node(h, fr);
            sr = await node(h, sr);
            while (f !== 0n && (f & 1n) === 0n) {
              f >>= 1n;
              s >>= 1n;
            }
          } else sr = await node(sr, h);
          f >>= 1n;
          s >>= 1n;
        }
        require(s === 0n &&
          same(fr, hex(a.root, 32)) &&
          same(sr, hex(b.root, 32)), "Merkle consistency root mismatch");
      }
      steps.push(`Append-only consistency · ${a.size} → ${b.size}`);
    }
    return {
      verified: true,
      steps,
      reason: "The signed claim matches the supplied trust anchor.",
    };
  } catch (e) {
    return { verified: false, steps, reason: e.message };
  }
}
async function api(path, data) {
  const response = await fetch("/api/" + path, {
    method: data === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + $("token").value,
    },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  const value = await response.json();
  if (!response.ok) throw Error(value.error);
  return value;
}
async function task(fn) {
  if (busy) return;
  busy = true;
  $("error").textContent = "";
  document
    .querySelectorAll("button,input,textarea,select")
    .forEach((b) => (b.disabled = true));
  try {
    await fn();
  } catch (e) {
    $("error").textContent = "Action failed: " + e.message;
    $("connection").textContent = "CONNECTION NEEDS ATTENTION";
  } finally {
    busy = false;
    document
      .querySelectorAll("button,input,textarea,select")
      .forEach((b) => (b.disabled = false));
  }
}
function pending() {
  delete $("receipt").dataset.verified;
  delete $("receipt").dataset.agreement;
  $("receipt").className = "";
  $("receipt").replaceChildren();
  const p = document.createElement("p");
  p.className = "pending";
  p.textContent = "No verdict yet. The bundle has not been checked.";
  $("receipt").append(p);
}
async function refresh() {
  state = await api("state");
  $("connection").textContent = "LOCAL LOG CONNECTED";
  $("size").textContent = state.size;
  $("root").textContent = state.checkpoint.root;
  $("checkpoint").textContent =
    "Signed at entry count " + state.checkpoint.size;
  if (!$("public-key").value) $("public-key").value = state.public_key;
  if (!$("log-id").value) $("log-id").value = state.log_id;
  $("index").max = state.size - 1;
  const previous = $("old").value;
  $("old").replaceChildren();
  for (const c of state.checkpoints) {
    const option = document.createElement("option");
    option.value = c.size;
    option.textContent = "Tree size " + c.size;
    $("old").append(option);
  }
  if (state.checkpoints.some((c) => String(c.size) === previous))
    $("old").value = previous;
  else $("old").value = state.checkpoints[0].size;
  $("entries").replaceChildren();
  for (const entry of state.entries) {
    const row = document.createElement("button");
    row.className = "entry-row";
    const number = document.createElement("span");
    number.textContent = String(entry.seq).padStart(3, "0");
    const text = document.createElement("strong");
    text.textContent = entry.payload_text;
    const hash = document.createElement("code");
    hash.textContent = entry.hash.slice(0, 12) + "…";
    row.append(number, text, hash);
    row.onclick = () =>
      task(async () => {
        $("index").value = entry.seq;
        setKind("inclusion");
        await load();
      });
    $("entries").append(row);
  }
}
function setKind(value) {
  kind = value;
  $("inclusion").setAttribute("aria-pressed", String(kind === "inclusion"));
  $("consistency").setAttribute("aria-pressed", String(kind === "consistency"));
  $("flip").hidden = kind !== "inclusion";
  pending();
}
async function load() {
  const proofs = await api(
    "bundle?index=" + $("index").value + "&old=" + $("old").value,
  );
  bundle = proofs[kind];
  $("bundle").value = JSON.stringify(bundle, null, 2);
  pending();
}
async function verify() {
  pending();
  const snapshot = $("bundle").value,
    proof = JSON.parse(snapshot),
    selectedKind = kind,
    key = $("public-key").value.trim(),
    id = $("log-id").value.trim();
  const [local, rust] = await Promise.all([
    browserVerify(proof, key, id),
    api("verify", { kind, bundle: proof, public_key: key, log_id: id }),
  ]);
  const agreement = local.verified === rust.verified,
    valid = agreement && local.verified;
  if (
    snapshot !== $("bundle").value ||
    key !== $("public-key").value.trim() ||
    id !== $("log-id").value.trim() ||
    kind !== selectedKind
  ) {
    pending();
    return;
  }
  $("receipt").className = valid ? "valid" : "invalid";
  $("receipt").replaceChildren();
  const title = document.createElement("h3");
  title.textContent = valid ? "VERIFIED" : "REJECTED";
  const explanation = document.createElement("p");
  explanation.textContent = agreement
    ? local.reason
    : "Verifiers disagree. This claim is rejected.";
  const list = document.createElement("ol");
  for (const step of local.steps) {
    const item = document.createElement("li");
    item.textContent = step;
    list.append(item);
  }
  const note = document.createElement("small");
  note.textContent = agreement
    ? "Rust and browser WebCrypto agree."
    : "Do not accept this proof.";
  $("receipt").append(title, explanation, list, note);
  $("receipt").dataset.verified = String(valid);
  $("receipt").dataset.agreement = String(agreement);
}
$("inclusion").onclick = () =>
  task(async () => {
    setKind("inclusion");
    await load();
  });
$("consistency").onclick = () =>
  task(async () => {
    setKind("consistency");
    await load();
  });
$("load").onclick = () => task(load);
$("verify").onclick = () => task(verify);
$("reconnect").onclick = () =>
  task(async () => {
    await refresh();
    await load();
  });
$("append").onclick = () =>
  task(async () => {
    await api("append", {});
    await refresh();
    await load();
  });
$("flip").onclick = () => {
  try {
    const p = JSON.parse($("bundle").value);
    require(p.entry.payload.length >= 2, "Payload is empty");
    p.entry.payload =
      (p.entry.payload.startsWith("00") ? "01" : "00") +
      p.entry.payload.slice(2);
    $("bundle").value = JSON.stringify(p, null, 2);
    pending();
  } catch (e) {
    $("error").textContent = e.message;
  }
};
$("drop").onclick = () => {
  try {
    const p = JSON.parse($("bundle").value);
    p.path.pop();
    $("bundle").value = JSON.stringify(p, null, 2);
    pending();
  } catch (e) {
    $("error").textContent = e.message;
  }
};
$("reorder").onclick = () => {
  try {
    const p = JSON.parse($("bundle").value);
    require(p.path.length >= 2, "Need at least two proof nodes");
    [p.path[0], p.path[1]] = [p.path[1], p.path[0]];
    $("bundle").value = JSON.stringify(p, null, 2);
    pending();
  } catch (e) {
    $("error").textContent = e.message;
  }
};
$("bundle").oninput = pending;
$("public-key").oninput = pending;
$("log-id").oninput = pending;
$("download").onclick = () => {
  const blob = new Blob([$("bundle").value], { type: "application/json" }),
    url = URL.createObjectURL(blob),
    link = document.createElement("a");
  link.href = url;
  link.download = "seal-" + kind + ".json";
  link.click();
  URL.revokeObjectURL(url);
};
await task(async () => {
  await refresh();
  await load();
});

/* Context motion: served inside the existing whitelisted asset. */
(()=>{
/** Finite, event-driven motion. No entrance timeline, polling, layout reads, or content delays. */
function installMotion(profile) {
    const preference = matchMedia('(prefers-reduced-motion: no-preference)');
    const running = new Set();
    const owned = new WeakMap();
    let observer;
    let events;
    let frame = 0;
    let interacted = false;
    const pending = new Map();
    const snapshots = new WeakMap();
    document.documentElement.dataset.motionProfile = profile.name;
    const play = (element, frames, duration) => {
        if (!preference.matches || !element.isConnected || document.hidden || typeof element.animate !== 'function')
            return;
        if (!(element instanceof HTMLElement) || element.matches('input,textarea,[contenteditable],.drag-handle,.note-body') || element.querySelector('input:focus,textarea:focus,[contenteditable]:focus'))
            return;
        // Stream updates never restart an in-flight effect; each owns at most one compositor animation.
        if (owned.get(element)?.playState === 'running')
            return;
        const animation = element.animate(frames, { duration, easing: 'cubic-bezier(0.16, 1, 0.3, 1)', iterations: 1, fill: 'none' });
        owned.set(element, animation);
        running.add(animation);
        const clear = () => { running.delete(animation); if (owned.get(element) === animation)
            owned.delete(element); };
        animation.onfinish = clear;
        animation.oncancel = clear;
    };
    const flush = () => {
        frame = 0;
        for (const [rule, groups] of pending)
            for (const group of groups) {
                const targets = rule.targets === ':self' ? [group] : Array.from(group.querySelectorAll(rule.targets)).slice(0, 6);
                const history = snapshots.get(group) || new Map();
                const previous = history.get(rule) || [];
                const current = [];
                for (const [index, target] of targets.entries()) {
                    const signature = (group.getAttribute('class') || '') + '|' + group.hasAttribute('open') + '|' + (target.textContent || '').slice(0, 2048) + '|' + target.getAttribute('class') + '|' + target.getAttribute('aria-pressed') + '|' + target.getAttribute('aria-current');
                    current.push(signature);
                    if (previous[index] !== signature) {
                        if (interacted)
                            play(target, rule.frames, rule.duration);
                    }
                }
                history.set(rule, current);
                snapshots.set(group, history);
            }
        pending.clear();
    };
    const enqueue = (rule, group) => {
        if (!group)
            return;
        if (!pending.has(rule))
            pending.set(rule, new Set());
        const groups = pending.get(rule);
        if (groups.size < 4)
            groups.add(group);
        if (!frame)
            frame = requestAnimationFrame(flush);
    };
    const stop = () => {
        observer?.disconnect();
        events?.abort();
        if (frame)
            cancelAnimationFrame(frame);
        frame = 0;
        pending.clear();
        for (const animation of running)
            animation.cancel();
        running.clear();
    };
    const start = () => {
        stop();
        if (!preference.matches)
            return;
        events = new AbortController();
        const signal = events.signal;
        const press = (event) => {
            if (event instanceof KeyboardEvent && !['Enter', ' '].includes(event.key))
                return;
            const source = event.target instanceof Element ? event.target : null;
            const control = source?.closest('button,summary,a.button');
            if (!control || control.matches(':disabled,[aria-disabled="true"],.drag-handle,.note-body'))
                return;
            interacted = true;
            play(control, profile.press, 160);
            if (control.matches(profile.neighbors)) {
        const neighbors = [control.previousElementSibling, control.nextElementSibling];
        for (const [index, sibling] of neighbors.entries()) {
          if (!sibling || !sibling.matches(profile.neighbors)) continue;
          const displacement = index === 0 ? -2 : 2;
          play(sibling, [{transform:'translateX(0) scaleX(1)'}, {transform:'translateX('+displacement+'px) scaleX(0.985)',offset:0.28}, {transform:'translateX(0) scaleX(1)'}], 190);
        }
      }
        };
        // Animate only once click targeting is committed; shrinking a pressed hitbox can otherwise lose edge clicks.
        document.addEventListener('click', press, { capture: true, signal });
        document.addEventListener('keydown', press, { capture: true, signal });
        for (const event of ['click', 'change'])
            document.addEventListener(event, () => { interacted = true; }, { capture: true, signal });
        observer = new MutationObserver(records => {
            for (const record of records) {
                const source = record.target instanceof Element ? record.target : record.target.parentElement;
                if (!source)
                    continue;
                for (const rule of profile.rules) {
                    enqueue(rule, source.closest(rule.watch));
                    for (const added of Array.from(record.addedNodes).slice(0, 6))
                        if (added instanceof Element) {
                            enqueue(rule, added.matches(rule.watch) ? added : added.querySelector(rule.watch));
                        }
                }
            }
        });
        observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['class', 'aria-current', 'aria-pressed', 'open'] });
    };
    preference.addEventListener('change', () => preference.matches ? start() : stop());
    window.addEventListener('pagehide', stop, { once: true });
    window.addEventListener('pageshow', event => { if (event.persisted && preference.matches)
        start(); });
    start();
}
installMotion({
    "name": "seal",
    "press": [
        {
            "transform": "translateY(0)"
        },
        {
            "transform": "translateY(1px)",
            "offset": 0.2
        },
        {
            "transform": "translateY(0)"
        }
    ],
    "neighbors": ".proof-modes button",
    "rules": [
        {
            "watch": "#receipt",
            "targets": "h3",
            "frames": [
                {
                    "transform": "rotate(-3deg) scale(1.04)"
                },
                {
                    "transform": "rotate(0deg) scale(1)"
                }
            ],
            "duration": 180
        },
        {
            "watch": "#entries",
            "targets": ".entry-row:first-child strong,.entry-row:first-child code",
            "frames": [
                {
                    "transform": "translateX(5px)"
                },
                {
                    "transform": "translateX(0)"
                }
            ],
            "duration": 190
        },
        {
            "watch": ".log-facts",
            "targets": "dd",
            "frames": [
                {
                    "transform": "translateX(-4px)"
                },
                {
                    "transform": "translateX(0)"
                }
            ],
            "duration": 160
        }
    ]
});

})();
