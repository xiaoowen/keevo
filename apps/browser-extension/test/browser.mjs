// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 真实浏览器测试：无头 Chrome 加载扩展（DevTools 协议的管道模式），经真实的 native host 与开发服务配对，
// 在本机 HTTP 测试页上用可信的鼠标事件操作页内菜单，并检查点击劫持防护（docs/security.md §12）：
//
// - 正常流程：聚焦输入框 → 图标 → 菜单 → 选择条目 → 填入用户名与密码；
// - 菜单出现后立刻点击（不足 500 毫秒）：不填充；
// - 页面把菜单调成几乎透明、或用自己的顶层元素盖住菜单：IntersectionObserver v2 判定不可见，不填充，
//   菜单关闭并提示改用弹窗；
// - 跨域 iframe 中的登录框：菜单提示嵌入关系，第一次点击只要求确认，第二次才填充。
//
// 由 scripts/build-extension.sh --test 调用；没有 Chrome 时跳过。

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { attach, click, launchChrome, waitFor } from "./cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const CHROME = process.env.KEEVO_CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const EXT_ID = "boojggkmhkakoacccigoiibnlkffcpof";
if (!existsSync(CHROME)) {
  console.log("没有找到 Chrome，跳过真实浏览器测试（可用 KEEVO_CHROME 指定）");
  process.exit(0);
}

const dir = mkdtempSync(join(tmpdir(), "kvbr"));
/** 清理按登记的相反顺序进行：先结束 Chrome 与开发服务，再删除临时目录。 */
const cleanups = [() => rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })];
async function cleanup() {
  while (cleanups.length) await cleanups.pop()();
}
process.on("unhandledRejection", async (e) => {
  console.error(e);
  await cleanup();
  process.exit(1);
});
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

// ---- 测试页

const FORM = `<form onsubmit="return false"><p><input id="u" name="username" autocomplete="username" style="width:280px;height:32px"></p><p><input id="p" type="password" autocomplete="current-password" style="width:280px;height:32px"></p><button>登录</button></form>`;
const ATTACKS = {
  // 页面把 Keevo 的顶层宿主调成几乎透明
  opacity: `<script>new MutationObserver(() => { for (const el of document.querySelectorAll("div[popover]")) el.style.setProperty("opacity", "0.05", "important"); }).observe(document.documentElement, { childList: true });</script>`,
  // 菜单出现后，页面用自己的顶层元素盖住它；pointer-events: none 让点击穿过去落在菜单上。
  // 持久的攻击者：每当 Keevo 把菜单重新放到最上面，就再把诱饵放回最上面
  cover: `<div id="decoy" popover="manual" style="position:fixed;inset:0;width:100vw;height:100vh;margin:0;border:0;background:#fff;pointer-events:none;font:32px sans-serif">点这里领取奖品</div><script>const d = document.getElementById("decoy"); const raise = () => { if (d.matches(":popover-open")) d.hidePopover(); d.showPopover(); }; new MutationObserver(() => { if (document.querySelectorAll("div[popover]:not(#decoy)").length >= 2) raise(); }).observe(document.documentElement, { childList: true }); document.addEventListener("toggle", (e) => { if (e.target !== d && e.newState === "open" && document.querySelectorAll("div[popover]:not(#decoy)").length >= 2) setTimeout(raise, 0); }, true);</script>`,
};
// 对照：与菜单不重叠的元素不应让菜单失效（避免误报）
const BENIGN = {
  // 只盖一次的诱饵：Keevo 把菜单重新放到最上面后，用户看到的就是真菜单，可以正常填充
  "cover-once": `<div id="decoy" popover="manual" style="position:fixed;inset:0;width:100vw;height:100vh;margin:0;border:0;background:#fff;pointer-events:none;font:32px sans-serif">点这里领取奖品</div><script>new MutationObserver(() => { if (document.querySelectorAll("div[popover]:not(#decoy)").length >= 2) { const d = document.getElementById("decoy"); if (!d.matches(":popover-open")) d.showPopover(); } }).observe(document.documentElement, { childList: true });</script>`,
  // 菜单出现之后，在右下角弹出一个顶层通知（位于菜单之上，但不重叠）
  toast: `<div id="decoy" popover="manual" style="position:fixed;inset:auto 16px 16px auto;width:200px;height:40px;margin:0;background:#333;color:#fff">已保存</div><script>new MutationObserver(() => { if (document.querySelectorAll("div[popover]:not(#decoy)").length >= 2) { const d = document.getElementById("decoy"); if (!d.matches(":popover-open")) d.showPopover(); } }).observe(document.documentElement, { childList: true });</script>`,
  // 页面自己的固定定位元素（不在顶层），远离菜单
  fixed: `<div style="position:fixed;right:16px;bottom:16px;width:200px;height:40px;background:#333;color:#fff;z-index:2147483647">在线客服</div>`,
};
const html = (body) => `<!doctype html><meta charset="utf-8"><title>测试</title><body style="margin:40px;font:16px sans-serif">${body}</body>`;

const server = createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  const port = server.address().port;
  const pages = {
    "/login": html(FORM),
    "/opacity": html(FORM + ATTACKS.opacity),
    "/cover": html(FORM + ATTACKS.cover),
    "/toast": html(FORM + BENIGN.toast),
    "/cover-once": html(FORM + BENIGN["cover-once"]),
    "/fixed": html(FORM + BENIGN.fixed),
    "/frame": html(
      `<p>嵌入的登录框：</p><iframe id="fr" src="http://localhost:${port}/login" style="width:600px;height:460px;border:0"></iframe>`,
    ),
  };
  res.writeHead(pages[path] ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
  res.end(pages[path] ?? "not found");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
cleanups.push(() => server.close());
const PORT = server.address().port;
const LOCAL = `http://localhost:${PORT}`;

// ---- 开发服务（自动确认配对与授权）

const env = { ...process.env, KEEVO_DEV_SOCKET: join(dir, "ipc", "k.sock") };
const service = spawn(join(root, "target/debug/keevo-dev-service"), ["--auto-confirm", "--dir", join(dir, "svc"), "--local-url", LOCAL], {
  env,
  stdio: ["ignore", "pipe", "pipe"],
});
let serviceLog = "";
service.stderr.on("data", (d) => (serviceLog += d));
cleanups.push(() => service.kill());
await new Promise((resolve, reject) => {
  service.stdout.on("data", (d) => String(d).includes("READY") && resolve());
  service.on("exit", (code) => reject(new Error(`开发服务提前退出：${code}\n${serviceLog}`)));
});

// ---- Chrome：独立的用户目录，native host 清单放在其中（不碰用户自己的 Chrome 配置）

const profile = join(dir, "profile");
mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
writeFileSync(
  join(profile, "NativeMessagingHosts", "io.github.xiaoowen.keevo.json"),
  JSON.stringify({
    name: "io.github.xiaoowen.keevo",
    description: "Keevo（测试）",
    path: join(root, "target/debug/keevo-native-host"),
    type: "stdio",
    allowed_origins: [`chrome-extension://${EXT_ID}/`],
  }),
);
// 测试用的扩展副本：网站权限改为安装时授予，省去权限弹窗（权限请求本身在弹窗中由用户操作）
const ext = join(dir, "ext");
cpSync(join(here, "..", "dist"), ext, { recursive: true });
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
manifest.host_permissions = manifest.optional_host_permissions;
writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));

const browser = await launchChrome(
  CHROME,
  ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", `--user-data-dir=${profile}`, "--window-size=1200,900", "about:blank"],
  env,
);
cleanups.push(() => browser.close());

console.log("真实浏览器测试（Chrome → 扩展 → native host → 开发服务）");
const { id } = await browser.send("Extensions.loadUnpacked", { path: ext });
assert.equal(id, EXT_ID, "扩展 ID 由清单中的公钥固定");
ok("无头 Chrome 加载扩展，ID 与 host 清单中的一致");

async function open(url) {
  const { targetId } = await browser.send("Target.createTarget", { url });
  const page = await attach(browser, targetId);
  await browser.send("Target.activateTarget", { targetId });
  // 无头模式下页面不会获得焦点：模拟焦点，focus() 才会触发焦点事件
  await page.send("Emulation.setFocusEmulationEnabled", { enabled: true });
  return page;
}

// ---- 配对（弹窗作为普通标签页打开）

const popup = await open(`chrome-extension://${EXT_ID}/popup.html`);
await waitFor(() => popup.eval(`!!document.getElementById("pair-name")`), "配对表单").catch(async (e) => {
  throw new Error(`${e.message}\n弹窗内容：${await popup.eval("document.body.innerText")}`);
});
await popup.eval(`[...document.querySelectorAll("button")].find((b) => b.textContent === "与 Keevo 配对").click()`);
await waitFor(
  () => popup.eval(`chrome.storage.local.get("servicePublic").then((r) => !!r.servicePublic)`),
  `配对完成\n${serviceLog}`,
  15000,
);
ok("经真实的 native host 与开发服务完成配对");

// ---- 页内菜单的操作

const used = new Set();
/** 新出现的页内菜单（扩展源的 iframe，是独立的目标）。 */
async function menuFrame() {
  const target = await waitFor(
    async () => {
      const { targetInfos } = await browser.send("Target.getTargets");
      return targetInfos.find((t) => t.type === "iframe" && t.url.endsWith("/menu.html") && !used.has(t.targetId));
    },
    "菜单 iframe",
    2000,
  );
  used.add(target.targetId);
  return attach(browser, target.targetId);
}

/** 在 `frame`（页面或其中的 iframe）中聚焦用户名，点击图标，返回菜单及其在页面中的位置。 */
async function openMenu(page, frame = page, offset = { x: 0, y: 0 }) {
  const input = await waitFor(async () => {
    await frame.eval(`document.getElementById("u").focus()`);
    return frame.eval(
      `(() => { const hosts = document.querySelectorAll("div[popover]:not(#decoy)"); if (hosts.length < 1) return null; const r = document.getElementById("u").getBoundingClientRect(); return { right: r.right, top: r.top, height: r.height }; })()`,
    );
  }, "输入框旁的图标");
  // 图标刚出现时可能还没摆好位置：菜单没有出现就再点一次
  let menu = null;
  for (let attempt = 0; attempt < 3 && !menu; attempt++) {
    await sleep(150);
    await click(page, offset.x + input.right - 16, offset.y + input.top + input.height / 2);
    menu = await menuFrame().catch(() => null);
  }
  if (!menu) {
    const state = await frame.eval(`({ hosts: document.querySelectorAll("div[popover]").length, active: document.activeElement?.id })`);
    throw new Error(`点击图标后没有出现菜单：${JSON.stringify(state)}`);
  }
  const host = await waitFor(
    () =>
      frame.eval(
        `(() => { const hosts = [...document.querySelectorAll("div[popover]:not(#decoy)")]; if (hosts.length < 2) return null; const r = hosts.at(-1).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
      ),
    "菜单宿主",
  );
  await waitFor(() => menu.eval(`!!document.querySelector("button.item")`), "菜单条目");
  const button = await menu.eval(
    `(() => { const r = document.querySelector("button.item").getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`,
  );
  return { menu, at: { x: offset.x + host.x + button.x, y: offset.y + host.y + button.y } };
}

const values = (frame) => frame.eval(`[document.getElementById("u").value, document.getElementById("p").value]`);
const filled = ["admin", "demo-local-password"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** 设置 KEEVO_SHOTS=<目录> 时保存截图，用于人工检查排版。 */
async function shot(page, name) {
  if (!process.env.KEEVO_SHOTS) return;
  const { data } = await page.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(process.env.KEEVO_SHOTS, `${name}.png`), Buffer.from(data, "base64"));
}

// 1. 正常流程，以及过早的点击
{
  const page = await open(`${LOCAL}/login`);
  const { menu, at } = await openMenu(page);
  assert.equal(await menu.eval(`document.querySelector(".site").textContent`), `localhost:${PORT}`);
  // 页面拿不到图标与菜单：宿主的 shadow root 是封闭的，菜单是扩展源的 iframe
  assert.equal(await page.eval(`[...document.querySelectorAll("div[popover]")].every((h) => h.shadowRoot === null)`), true);
  const early = !(await menu.eval(`document.body.classList.contains("armed")`));
  await click(page, at.x, at.y);
  await sleep(400);
  if (early) assert.deepEqual(await values(page), ["", ""], "菜单出现不足 500 毫秒时的点击不填充");
  ok(early ? "菜单显示输入框所在的网站，页面读不到其内容；出现不足 500 毫秒时的点击被忽略" : "菜单显示输入框所在的网站，页面读不到其内容（机器较慢，跳过过早点击的检查）");
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "菜单可用（可见满 500 毫秒）");
  await shot(page, "menu");
  await click(page, at.x, at.y);
  await waitFor(async () => JSON.stringify(await values(page)) === JSON.stringify(filled), "填入用户名与密码");
  await waitFor(() => page.eval(`document.querySelectorAll("div[popover]").length <= 1`), "填充后菜单关闭");
  ok("可信点击图标与条目后填入用户名与密码，菜单关闭");
}

// 2. 点击劫持：透明与遮挡
for (const [path, what] of [
  ["/opacity", "页面把菜单调成几乎透明"],
  ["/cover", "页面反复用自己的顶层元素盖住菜单"],
]) {
  const page = await open(`${LOCAL}${path}`);
  const { menu, at } = await openMenu(page);
  await sleep(1200);
  await shot(page, `attack-${path.slice(1)}`);
  assert.equal(await menu.eval(`document.body.classList.contains("armed")`), false, `${what}：菜单判定为不可见`);
  await click(page, at.x, at.y);
  await sleep(800);
  assert.deepEqual(await values(page), ["", ""], `${what}：不填充`);
  await waitFor(() => page.eval(`document.querySelectorAll("div[popover]:not(#decoy)").length <= 1`), `${what}：菜单关闭`);
  const blocked = await popup.eval(
    `chrome.storage.session.get(null).then((all) => Object.keys(all).some((k) => k.startsWith("blocked:")))`,
  );
  assert.equal(blocked, true, `${what}：记下改用弹窗的提示`);
  ok(`${what}：判定不可见，点击不填充，菜单关闭并提示改用弹窗`);
}

// 3. 对照：不重叠的顶层通知与固定元素不影响菜单
for (const [path, what] of [
  ["/toast", "菜单之后打开、不重叠的顶层通知"],
  ["/fixed", "远离菜单的固定定位元素"],
  ["/cover-once", "只盖一次的顶层诱饵（菜单被放回最上面）"],
]) {
  const page = await open(`${LOCAL}${path}`);
  const { menu, at } = await openMenu(page);
  await shot(page, `benign-${path.slice(1)}`);
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), `${what}：菜单可用`, 3000);
  await click(page, at.x, at.y);
  await waitFor(async () => JSON.stringify(await values(page)) === JSON.stringify(filled), `${what}：正常填充`);
  ok(`对照：${what}不影响菜单，正常填充`);
}

// 4. 跨域 iframe 中的登录框
{
  const page = await open(`http://127.0.0.1:${PORT}/frame`);
  const target = await waitFor(async () => {
    const { targetInfos } = await browser.send("Target.getTargets");
    return targetInfos.find((t) => t.type === "iframe" && t.url === `${LOCAL}/login`);
  }, "嵌入的登录页");
  const frame = await attach(browser, target.targetId);
  await waitFor(() => frame.eval(`document.readyState === "complete"`), "嵌入的登录页加载");
  const offset = await page.eval(
    `(() => { const r = document.getElementById("fr").getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
  );
  const { menu, at } = await openMenu(page, frame, offset);
  const warning = await menu.eval(`document.querySelector(".banner.warning")?.textContent ?? ""`);
  assert.match(warning, new RegExp(`嵌在 127\\.0\\.0\\.1:${PORT} 的页面中，来自 localhost:${PORT}`));
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "菜单可用");
  await shot(page, "menu-frame");
  await click(page, at.x, at.y);
  await waitFor(() => menu.eval(`!!document.querySelector(".confirm")`), "要求再次确认");
  assert.deepEqual(await values(frame), ["", ""], "第一次点击只要求确认");
  // 用户读完确认提示再点：菜单改变高度后重新满足可见时间
  await sleep(700);
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "确认后菜单可用");
  const again = await menu.eval(
    `(() => { const r = document.querySelector("button.item").getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`,
  );
  const host = await frame.eval(
    `(() => { const r = [...document.querySelectorAll("div[popover]")].at(-1).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
  );
  await click(page, offset.x + host.x + again.x, offset.y + host.y + again.y);
  await waitFor(async () => JSON.stringify(await values(frame)) === JSON.stringify(filled), "确认后填入");
  ok("跨域 iframe：菜单写明嵌入关系，第一次点击只要求确认，确认后填入");
}

// 5. 弹窗填充：与页内菜单共用内容脚本中的同一份填充实现（填入当前标签页中第一个可见的登录表单）
{
  const page = await open(`${LOCAL}/login`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "登录页加载");
  // 弹窗页（作为标签页打开）向 Service Worker 发请求；"当前标签页"是刚激活的登录页
  const result = await popup.eval(`(async () => {
    const c = await chrome.runtime.sendMessage({ type: "candidates" });
    const item = c.candidates.find((x) => x.title === "本地开发（演示）");
    return chrome.runtime.sendMessage({ type: "fill", itemId: item.item_id });
  })()`);
  assert.equal(result.fill, "filled");
  assert.deepEqual(await values(page), filled);
  ok("弹窗填充经内容脚本填入当前标签页的登录表单");
}

console.log(`全部通过（${checks} 项）`);
await cleanup();
process.exit(0);
