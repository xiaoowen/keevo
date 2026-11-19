// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 扩展侧端到端测试：加载扩展实际使用的 WASM 产物（dist/wasm），像 Chrome 那样启动真实的
// keevo-native-host，经 Unix socket 连接开发服务（keevo-dev-service），完成配对、查询与填充。
//
// 由 scripts/build-extension.sh --test 调用。Node 不是 Chrome，因此用仅 debug 构建生效的
// 环境变量跳过 native host 的父进程校验。

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const { initSync, KeevoClient } = await import(join(here, "..", "dist", "wasm", "keevo_wasm.js"));
initSync({ module: readFileSync(join(here, "..", "dist", "wasm", "keevo_wasm_bg.wasm")) });

const ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const dir = mkdtempSync(join(tmpdir(), "kvjs"));
const env = {
  ...process.env,
  KEEVO_DEV_SOCKET: join(dir, "ipc", "k.sock"),
  KEEVO_DEV_ALLOW_ANY_PARENT: "1",
};

const service = spawn(join(root, "target/debug/keevo-dev-service"), ["--auto-confirm", "--dir", dir], {
  env,
  stdio: ["ignore", "pipe", "inherit"],
});
const cleanup = () => {
  service.kill();
  rmSync(dir, { recursive: true, force: true });
};
process.on("exit", cleanup);

await new Promise((resolve, reject) => {
  service.stdout.on("data", (d) => String(d).includes("READY") && resolve());
  service.on("exit", (code) => reject(new Error(`开发服务提前退出：${code}`)));
});

/** 像 Chrome 一样启动 native host：4 字节本机字节序（小端）长度 + UTF-8 JSON。 */
function launchHost() {
  const host = spawn(join(root, "target/debug/keevo-native-host"), [ORIGIN], { env, stdio: ["pipe", "pipe", "inherit"] });
  let buf = Buffer.alloc(0);
  const waiting = [];
  const frames = [];
  host.stdout.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32LE(0)) {
      const len = buf.readUInt32LE(0);
      const frame = buf.subarray(4, 4 + len).toString("utf8");
      buf = buf.subarray(4 + len);
      const w = waiting.shift();
      if (w) w(frame);
      else frames.push(frame);
    }
  });
  return {
    send(json) {
      const body = Buffer.from(json, "utf8");
      const head = Buffer.alloc(4);
      head.writeUInt32LE(body.length, 0);
      host.stdin.write(Buffer.concat([head, body]));
    },
    recv() {
      const f = frames.shift();
      return f !== undefined ? Promise.resolve(f) : new Promise((r) => waiting.push(r));
    },
    close() {
      host.stdin.end();
      return new Promise((r) => host.on("exit", r));
    },
  };
}

async function exchange(host, client, frame) {
  host.send(frame);
  const out = JSON.parse(client.onFrame(await host.recv()));
  for (const f of out.frames) host.send(f);
  return out.events;
}

async function call(host, client, method, params) {
  const { id, frame } = JSON.parse(client.request(JSON.stringify(params ? { method, params } : { method })));
  const [event] = await exchange(host, client, frame);
  assert.equal(event.type, "message");
  assert.equal(event.message.id, id);
  return event.message;
}

let checks = 0;
const ok = (msg) => {
  checks += 1;
  console.log(`  ✓ ${msg}`);
};

console.log("扩展侧端到端测试（WASM → native host → socket → 开发服务）");

// ---- 显示名清洗：与 Keevo.app 同一规则（spec/ipc.md §4.2）
assert.equal(KeevoClient.displayName("Chrome\u202e · \u200b工作\u0007"), "Chrome · 工作");
assert.equal([...KeevoClient.displayName("名".repeat(100))].length, 64);
ok("显示名去掉双向控制符、零宽字符与控制字符，最多 64 个字符");

// ---- 首次配对
let host = launchHost();
let client = new KeevoClient(undefined, ORIGIN, "Node 测试");
const extKey = client.privateKeyHex();
host.send(client.hello());
let events = await exchange(host, client, client.startPairing());
assert.equal(events[0].type, "show_sas");
assert.match(events[0].sas, /^[0-9a-f]{12}$/);
// 配对码的 6 个词：按发布的词表独立查一遍，与 WASM 给出的一致（Keevo.app 用同一份 Rust 词表）
const wordlist = readFileSync(join(root, "spec/sas-wordlist-v1.tsv"), "utf8").trimEnd().split("\n").map((l) => l.split("\t"));
assert.equal(wordlist.length, 256);
const expected = events[0].sas.match(/../g).map((h) => {
  const [index, en, zh] = wordlist[parseInt(h, 16)];
  assert.equal(parseInt(index, 16), parseInt(h, 16));
  return { zh, en };
});
assert.deepEqual(events[0].words, expected);
ok(`握手完成，显示配对码 ${expected.map((w) => w.zh).join(" ")}`);
events = JSON.parse(client.onFrame(await host.recv())).events;
assert.equal(events[0].type, "paired");
const servicePublic = events[0].service_public;
ok("开发服务确认配对，扩展收到服务公钥");

// ---- 查询与填充
let m = await call(host, client, "candidates", { url: "https://github.com/login" });
assert.equal(m.result.items.length, 1);
assert.equal(m.result.items[0].title, "GitHub（演示）");
const itemId = m.result.items[0].item_id;
ok("github.com 匹配到演示登录");

m = await call(host, client, "fill", { item_id: itemId, url: "https://github.com/login" });
assert.deepEqual([m.result.username, m.result.password], ["octocat", "demo-github-password"]);
ok("取得填充凭据");

m = await call(host, client, "fill", { item_id: itemId, url: "https://github.com.evil.example/login" });
assert.equal(m.error.code, "url_mismatch");
m = await call(host, client, "candidates", { url: "https://github.com.evil.example/login" });
assert.equal(m.result.items.length, 0);
ok("钓鱼网址既无候选，也拿不到凭据");

m = await call(host, client, "candidates", { url: "http://localhost:3000/" });
assert.equal(m.result.items.length, 1);
ok("本地开发服务按端口匹配");

// ---- 协议 v2：保存与更新（spec/ipc.md §5.5；开发服务自动确认更新）
assert.equal(client.version(), 2);
m = await call(host, client, "save", { url: "https://news.example/login?x=1", username: "reader", password: "saved-pass" });
const savedId = m.result.item_id;
assert.match(savedId, /^[0-9a-f]{32}$/);
m = await call(host, client, "candidates", { url: "https://news.example/" });
assert.deepEqual(m.result.items.map((i) => [i.title, i.subtitle]), [["news.example", "reader"]]);
m = await call(host, client, "fill", { item_id: savedId, url: "https://news.example/" });
assert.equal(m.result.password, "saved-pass");
ok("v2 保存新登录：标题取站点主机名，之后可以查到并填充");
m = await call(host, client, "update", { item_id: itemId, url: "https://github.com/settings", password: "rotated" });
assert.equal(m.result.item_id, itemId);
m = await call(host, client, "fill", { item_id: itemId, url: "https://github.com/login" });
assert.equal(m.result.password, "rotated");
m = await call(host, client, "update", { item_id: itemId, url: "https://github.com.evil.example/", password: "x" });
assert.equal(m.error.code, "url_mismatch");
ok("v2 更新密码（经 Keevo 确认）；网址不匹配时拒绝");
await host.close();
client.free();

// ---- 扩展重启：用保存的扩展密钥与服务公钥建立 IK 会话
host = launchHost();
client = new KeevoClient(extKey, ORIGIN, "Node 测试");
host.send(client.hello());
events = await exchange(host, client, client.startSession(servicePublic));
assert.equal(events[0].type, "established");
m = await call(host, client, "status");
assert.equal(m.result.locked, false);
ok("重启后用 IK 会话重新连接");
await host.close();

// ---- v1 会话：同一个配对仍可用，但消息集合里没有 save
host = launchHost();
const v1 = new KeevoClient(extKey, ORIGIN, "Node 测试", 1);
host.send(v1.hello());
events = await exchange(host, v1, v1.startSession(servicePublic));
assert.equal(events[0].type, "established");
assert.throws(() => v1.request(JSON.stringify({ method: "save", params: { url: "https://a.example/", username: "", password: "p" } })));
m = await call(host, v1, "status");
assert.equal(m.result.locked, false);
ok("v1 会话照常可用（配对与版本无关），但不能发送 v2 的 save");
await host.close();

// ---- 没有配对记录的扩展被拒绝
host = launchHost();
const stranger = new KeevoClient(undefined, ORIGIN, "陌生扩展");
host.send(client.hello());
events = await exchange(host, stranger, stranger.startSession(servicePublic));
assert.deepEqual(events[0], { type: "error", code: "not_paired" });
ok("未配对的扩展被拒绝");
await host.close();

console.log(`全部通过（${checks} 项）`);
process.exit(0);
