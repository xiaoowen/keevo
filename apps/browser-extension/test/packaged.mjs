// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 打包产物的真实浏览器测试：Chrome 启动应用包内经过签名的 native host，host 通过父进程校验（真实 Chrome 的
// 代码签名），连接 Vault Service；服务（keevo-smoke --browser-service，与 Keevo.app 链接同一份 Rust 静态库）
// 只接受 cdhash 编译进来的 host（spec/ipc.md §3.1）。
//
// - 反例：host 清单指向同一份代码、但没有经过打包签名的 host（cdhash 不同）：服务拒绝，配对不会开始；
// - 正例：应用包内的 host：完成配对、查询与填充（确认一律自动同意，事件由服务打印出来核对）。
//
// HOME 指向临时目录：服务的 socket（$HOME/Library/Application Support/Keevo/ipc）与 Chrome 都与用户的
// 真实配置隔离，也不会与正在运行的 Keevo.app 冲突。
//
// 用法：node packaged.mjs <Keevo.app> <keevo-smoke>（由 scripts/package-macos.sh --verify 调用）

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { attach, launchChrome, waitFor } from "./cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
// host 清单中的路径必须是绝对路径
const [APP, SMOKE] = process.argv.slice(2).map((p) => resolve(p));
const CHROME = process.env.KEEVO_CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const EXT_ID = "boojggkmhkakoacccigoiibnlkffcpof";
const BUNDLED_HOST = join(APP, "Contents/Helpers/keevo-native-host");
const UNSIGNED_HOST = join(root, "target/release/keevo-native-host");
for (const f of [BUNDLED_HOST, SMOKE, UNSIGNED_HOST, join(here, "..", "dist", "manifest.json")]) {
  assert.ok(existsSync(f), `缺少 ${f}`);
}

// Unix socket 路径有长度上限：HOME 用 /tmp 下的短路径
const home = mkdtempSync("/tmp/kvp-");
const cleanups = [() => rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })];
async function cleanup() {
  while (cleanups.length) await cleanups.pop()();
}
process.on("uncaughtException", async (e) => {
  console.error(e);
  await cleanup();
  process.exit(1);
});

let checks = 0;
const ok = (msg) => {
  checks += 1;
  console.log(`  ✓ ${msg}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const server = createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(
    `<!doctype html><meta charset="utf-8"><body><form onsubmit="return false"><input id="u" name="username"><input id="p" type="password"></form></body>`,
  );
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
cleanups.push(() => new Promise((r) => server.close(r)));
const LOCAL = `http://localhost:${server.address().port}`;

const env = { ...process.env, HOME: home };
const service = spawn(SMOKE, ["--browser-service", LOCAL], { env, stdio: ["pipe", "pipe", "inherit"] });
cleanups.push(() => service.stdin.end());
const events = [];
let out = "";
service.stdout.on("data", (d) => {
  out += d;
  for (const line of String(d).split("\n")) if (line.startsWith("EVENT ")) events.push(line.slice(6));
});
await waitFor(() => out.includes("READY") || out.includes("ERROR"), "服务启动", 30000);
assert.ok(out.includes("READY"), out);

const profile = join(home, "profile");
const hosts = join(profile, "NativeMessagingHosts");
mkdirSync(hosts, { recursive: true });
const useHost = (path) =>
  writeFileSync(
    join(hosts, "io.github.xiaoowen.keevo.json"),
    JSON.stringify({ name: "io.github.xiaoowen.keevo", description: "Keevo", path, type: "stdio", allowed_origins: [`chrome-extension://${EXT_ID}/`] }),
  );
const ext = join(home, "ext");
cpSync(join(here, "..", "dist"), ext, { recursive: true });
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
manifest.host_permissions = manifest.optional_host_permissions;
writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));

const browser = await launchChrome(
  CHROME,
  ["--headless=new", "--disable-gpu", "--no-first-run", "--use-mock-keychain", "--password-store=basic", `--user-data-dir=${profile}`, "about:blank"],
  env,
);
cleanups.push(() => browser.close());

console.log("打包产物的真实浏览器测试（Chrome → 应用包内的 host → cdhash 校验 → Vault Service）");
assert.equal((await browser.send("Extensions.loadUnpacked", { path: ext })).id, EXT_ID);

async function open(url) {
  const { targetId } = await browser.send("Target.createTarget", { url });
  const page = await attach(browser, targetId);
  await browser.send("Target.activateTarget", { targetId });
  return page;
}
const popup = await open(`chrome-extension://${EXT_ID}/popup.html`);
await waitFor(() => popup.eval(`!!document.getElementById("pair-name")`), "配对表单");
const pair = () => popup.eval(`chrome.runtime.sendMessage({ type: "pair", name: "打包测试" })`);
const paired = () => popup.eval(`chrome.storage.local.get("servicePublic").then((r) => !!r.servicePublic)`);

// 反例：cdhash 不在主程序中的 host。先停掉弹窗页自己的状态轮询，它会在出错后自动重连，掩盖断开的原因
useHost(UNSIGNED_HOST);
await popup.eval(`(() => { const top = setInterval(() => {}, 1000); for (let i = 0; i <= top; i++) clearInterval(i); })()`);
await pair();
await sleep(3000);
assert.equal(await paired(), false, "未经打包签名的 host 不能完成配对");
assert.equal(events.length, 0, `服务不应开始配对：${events.join("；")}`);
// host 连上了 socket、随后被服务关闭：扩展看到的是 disconnected（socket 不存在时 host 会回报 service_unavailable，
// 找不到 host 时为 host_not_installed）。用不会触发重连的请求读取状态
const state = await popup.eval(`chrome.runtime.sendMessage({ type: "display_name", name: "" }).then((r) => r.state)`);
assert.deepEqual(state, { status: "error", error: "disconnected" }, "host 连上 socket 后被服务关闭");
ok("没有经过打包签名的 host（cdhash 不同）被服务拒绝：配对没有开始");

// 正例：应用包内的 host
useHost(BUNDLED_HOST);
await pair();
await waitFor(paired, "配对完成", 15000).catch(async (e) => {
  const s = await popup.eval(`chrome.runtime.sendMessage({ type: "state" }).then((r) => r.state)`);
  throw new Error(`${e.message}\n服务事件：${events.join("；")}\n扩展状态：${JSON.stringify(s)}\nChrome 输出（末尾）：${browser.stderr().slice(-1500)}`);
});
assert.ok(events.some((e) => e.startsWith("pairing_started com.google.Chrome")), events.join("；"));
assert.ok(events.some((e) => e.startsWith("confirm_pairing 打包测试 ")), events.join("；"));
ok("应用包内的 host 通过父进程校验（真实 Chrome）与 cdhash 校验，完成配对");

const page = await open(`${LOCAL}/login`);
await waitFor(() => page.eval(`document.readyState === "complete"`), "登录页");
const result = await popup.eval(`(async () => {
  const c = await chrome.runtime.sendMessage({ type: "candidates" });
  const item = c.candidates.find((x) => x.subtitle === "admin");
  return chrome.runtime.sendMessage({ type: "fill", itemId: item.item_id });
})()`);
assert.equal(result.fill, "filled");
assert.deepEqual(await page.eval(`[document.getElementById("u").value, document.getElementById("p").value]`), ["admin", "packaged-pass"]);
assert.ok(events.some((e) => e.startsWith(`authorize_fill ${LOCAL} `)), events.join("；"));
ok("查询与填充经过站点授权，填入登录表单");

console.log(`全部通过（${checks} 项）`);
await cleanup();
process.exit(0);
