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
import { execFileSync, spawn } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { attach, click, findChromium, launchChrome, NO_CHROMIUM, waitFor } from "./cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const CHROME = findChromium();
const EXT_ID = "boojggkmhkakoacccigoiibnlkffcpof";
if (!CHROME) {
  console.log(`${NO_CHROMIUM}，跳过真实浏览器测试`);
  process.exit(0);
}

const dir = mkdtempSync(join(tmpdir(), "kvbr"));
/** 清理按登记的相反顺序进行：先结束 Chrome 与开发服务，再删除临时目录。 */
// 删除临时目录失败不影响测试结果：Chrome 被结束后，它的辅助进程可能还在写配置目录
const cleanups = [
  () => {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch (e) {
      console.warn(`  · 临时目录没有删除干净（${e.code ?? e.message}）：${dir}`);
    }
  },
];
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
// 会提交的表单（POST 到 /done），用于保存与更新
const POST_LOGIN = `<form method="post" action="/done"><p><input id="u" name="username" autocomplete="username" style="width:280px;height:32px"></p><p><input id="p" name="password" type="password" autocomplete="current-password" style="width:280px;height:32px"></p><button id="go" type="submit">登录</button></form>`;
const SIGNUP = `<form method="post" action="/done"><p><input id="u" name="username" autocomplete="username" style="width:280px;height:32px"></p><p><input id="p" type="password" autocomplete="new-password" style="width:280px;height:32px"></p><p><input id="p2" type="password" autocomplete="new-password" style="width:280px;height:32px"></p><button id="go" type="submit">注册</button></form>`;
const CHANGE = `<form method="post" action="/done"><input id="u" name="username" autocomplete="username" value="admin" hidden><p><input id="cur" type="password" autocomplete="current-password" style="width:280px;height:32px"></p><p><input id="p" type="password" autocomplete="new-password" style="width:280px;height:32px"></p><p><input id="p2" type="password" autocomplete="new-password" style="width:280px;height:32px"></p><button id="go" type="submit">修改密码</button></form>`;
const html = (body) => `<!doctype html><meta charset="utf-8"><title>测试</title><body style="margin:40px;font:16px sans-serif">${body}</body>`;

// 同站的测试要用 HTTPS（同站要求两边都是 HTTPS）：临时的自签名证书，Chrome 以 --ignore-certificate-errors 启动
execFileSync(
  "openssl",
  ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "tls.key"), "-out", join(dir, "tls.crt"), "-subj", "/CN=localhost", "-days", "2"],
  { stdio: "ignore" },
);
const tlsOptions = { key: readFileSync(join(dir, "tls.key")), cert: readFileSync(join(dir, "tls.crt")) };

const serve = (req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  const port = PORT;
  const pages = {
    "/login": html(FORM),
    "/opacity": html(FORM + ATTACKS.opacity),
    "/cover": html(FORM + ATTACKS.cover),
    "/toast": html(FORM + BENIGN.toast),
    "/cover-once": html(FORM + BENIGN["cover-once"]),
    "/fixed": html(FORM + BENIGN.fixed),
    "/post": html(POST_LOGIN),
    "/change": html(CHANGE),
    "/signup": html(SIGNUP),
    "/done": html("<p>已提交。</p>"),
    "/frame": html(
      `<p>嵌入的登录框：</p><iframe id="fr" src="http://localhost:${port}/login" style="width:600px;height:460px;border:0"></iframe>`,
    ),
    // 很矮的嵌入登录框（反馈：阿里云）：输入框上下都放不下完整的菜单
    "/login-short": html(FORM),
    "/frame-short": html(
      `<p>嵌入的登录框：</p><iframe id="fr" src="http://localhost:${port}/login-short" style="width:600px;height:200px;border:0"></iframe>`,
    ),
    // 多层嵌套：登录框的父帧不是顶层，菜单仍在登录框所在的帧中显示
    "/frame-nested": html(
      `<p>嵌套的登录框：</p><iframe id="fr" src="http://localhost:${port}/wrap" style="width:640px;height:260px;border:0"></iframe>`,
    ),
    "/wrap": html(`<iframe id="inner" src="/login-short" style="width:600px;height:200px;border:0"></iframe>`),
    // 同站（HTTPS、主机相同、端口不同）的矮登录框，外层带毛玻璃：复现阿里云（account.aliyun.com 中的 passport.aliyun.com）
    "/frame-same": html(
      `<div style="backdrop-filter:blur(6px);background:rgba(240,240,240,.7);padding:12px;border-radius:16px;width:600px"><iframe id="fr" src="https://localhost:${port}/login" style="width:600px;height:200px;border:0"></iframe></div>`,
    ),
  };
  res.writeHead(pages[path] ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
  res.end(pages[path] ?? "not found");
};
// 同一个端口上同时提供 HTTP 与 HTTPS（按第一个字节区分 TLS 握手）：演示条目的网址是 http://localhost:PORT，
// 按网址匹配规则也能用于 https://localhost:PORT
const server = createServer(serve);
const tls = createHttpsServer(tlsOptions, serve);
const mux = createNetServer((socket) => {
  socket.once("data", (head) => {
    socket.pause();
    socket.unshift(head);
    (head[0] === 0x16 ? tls : server).emit("connection", socket);
    process.nextTick(() => socket.resume());
  });
});
await new Promise((r) => mux.listen(0, "127.0.0.1", r));
cleanups.push(() => mux.close());
const PORT = mux.address().port;
const LOCAL = `http://localhost:${PORT}`;
// 另一个端口上的 HTTPS 顶层页面：与 https://localhost:PORT 同站、不同源
const topServer = createHttpsServer(tlsOptions, serve);
await new Promise((r) => topServer.listen(0, "127.0.0.1", r));
cleanups.push(() => topServer.close());
const SAME_SITE_TOP = `https://localhost:${topServer.address().port}`;

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

// 测试用的是 Playwright 的 Chromium（Chrome for Testing，没有 Google 的 Team ID），debug 构建的 host 因此跳过
// 父进程校验（只在 debug 构建生效）。真实 Chrome 的父进程校验由打包产物的测试 packaged.mjs 覆盖。
const browser = await launchChrome(
  CHROME,
  [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    `--user-data-dir=${profile}`,
    "--window-size=1200,900",
    // 同站测试用的自签名证书
    "--ignore-certificate-errors",
    "about:blank",
  ],
  { ...env, KEEVO_DEV_ALLOW_ANY_PARENT: "1" },
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

/**
 * 在 `frame`（页面或其中的 iframe）中聚焦用户名，点击图标，返回菜单及其在页面中的位置。`menuIn`：菜单宿主所在的文档
 * （直接嵌在顶层页面中的 iframe 由顶层页面显示菜单），`menuOffset` 是它在页面中的位置。
 */
async function openMenu(page, frame = page, offset = { x: 0, y: 0 }, subtitle = "admin", { menuIn = frame, menuOffset = offset } = {}) {
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
  // 与输入框同一文档时，第一个宿主是图标
  const least = menuIn === frame ? 2 : 1;
  const host = await waitFor(
    () =>
      menuIn.eval(
        `(() => { const hosts = [...document.querySelectorAll("div[popover]:not(#decoy)")]; if (hosts.length < ${least}) return null; const r = hosts.at(-1).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
      ),
    "菜单宿主",
  );
  await waitFor(() => menu.eval(`!!document.querySelector("button.item")`), "菜单条目");
  // 按用户名选择条目（保存测试之后，同一网站会有多个条目）
  const button = await waitFor(
    () =>
      menu.eval(
        `(() => { const b = [...document.querySelectorAll("button.item")].find((b) => b.querySelector(".subtitle")?.textContent === ${JSON.stringify(subtitle)}); if (!b) return null; const r = b.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`,
      ),
    `菜单中的「${subtitle}」`,
  );
  return { menu, at: { x: menuOffset.x + host.x + button.x, y: menuOffset.y + host.y + button.y } };
}

/** 与父帧同一进程的子帧（同站的 iframe 不是独立的目标）：在它的隔离环境中执行脚本（与页面共享 DOM）。 */
async function childFrame(parent, urlPart) {
  const info = await waitFor(async () => {
    const { frameTree } = await parent.send("Page.getFrameTree");
    const all = [];
    const walk = (t) => {
      all.push(t.frame);
      for (const c of t.childFrames ?? []) walk(c);
    };
    walk(frameTree);
    return all.find((f) => f.parentId && f.url.includes(urlPart));
  }, `子帧 ${urlPart}`);
  const { executionContextId } = await parent.send("Page.createIsolatedWorld", { frameId: info.id, worldName: "keevo-test" });
  return {
    async eval(expression) {
      const r = await parent.send("Runtime.evaluate", { expression, contextId: executionContextId, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(`页面脚本出错：${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    },
  };
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

// 4. 跨站 iframe 中的登录框：菜单由顶层页面显示（iframe 直接嵌在顶层页面中）
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
  const top = { menuIn: page, menuOffset: { x: 0, y: 0 } };
  const { menu, at } = await openMenu(page, frame, offset, "admin", top);
  assert.equal(await frame.eval(`document.querySelectorAll("div[popover]").length`), 1, "iframe 中只有图标，菜单在顶层页面中");
  const warning = await menu.eval(`document.querySelector(".banner.warning")?.textContent ?? ""`);
  assert.match(warning, new RegExp(`嵌在 127\\.0\\.0\\.1:${PORT} 的页面中`));
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
  const host = await page.eval(
    `(() => { const r = [...document.querySelectorAll("div[popover]")].at(-1).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
  );
  await click(page, host.x + again.x, host.y + again.y);
  await waitFor(async () => JSON.stringify(await values(frame)) === JSON.stringify(filled), "确认后填入");
  await waitFor(() => page.eval(`document.querySelectorAll("div[popover]").length === 0`), "填入后顶层页面中的菜单关闭");
  ok("跨站 iframe：菜单由顶层页面显示并写明嵌入关系，第一次点击只要求确认，确认后填入并关闭");
}

// 4b. 很矮的 iframe：菜单由顶层页面显示，不受 iframe 大小的限制
{
  const page = await open(`http://127.0.0.1:${PORT}/frame-short`);
  const target = await waitFor(async () => {
    const { targetInfos } = await browser.send("Target.getTargets");
    return targetInfos.find((t) => t.type === "iframe" && t.url === `${LOCAL}/login-short`);
  }, "矮的嵌入登录页");
  const frame = await attach(browser, target.targetId);
  await waitFor(() => frame.eval(`document.readyState === "complete"`), "矮的嵌入登录页加载");
  const offset = await page.eval(
    `(() => { const r = document.getElementById("fr").getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
  );
  const { menu } = await openMenu(page, frame, offset, "admin", { menuIn: page, menuOffset: { x: 0, y: 0 } });
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "矮的 iframe：菜单可用");
  // 菜单在用户名下方展开，超出 iframe 的底边
  const box = await page.eval(
    `(() => { const m = [...document.querySelectorAll("div[popover]")].at(-1).getBoundingClientRect(); const f = document.getElementById("fr").getBoundingClientRect(); return { menuTop: m.top, menuBottom: m.bottom, frameTop: f.top, frameBottom: f.bottom }; })()`,
  );
  assert.ok(box.menuTop > box.frameTop && box.menuBottom > box.frameBottom, `菜单的位置不对：${JSON.stringify(box)}`);
  await shot(page, "menu-frame-short");
  // Esc 关闭：两部分都关闭
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await waitFor(() => page.eval(`document.querySelectorAll("div[popover]").length === 0`), "Esc 后菜单关闭");
  ok("矮的 iframe：菜单由顶层页面显示，可以超出 iframe，完整可见后可以使用；Esc 关闭");
}

// 4c. 同站 iframe 外层带毛玻璃（反馈：阿里云）：iframe 祖先的 backdrop-filter 让 iframe 中的一切都被判为不可见，
// 菜单只能由顶层页面显示。同站不显示嵌入提示，点一次即填入
{
  const page = await open(`${SAME_SITE_TOP}/frame-same`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "同站嵌入页加载");
  const frame = await childFrame(page, `localhost:${PORT}/login`);
  await waitFor(() => frame.eval(`document.readyState === "complete" && !!document.getElementById("u")`), "同站嵌入的登录页加载");
  const offset = await page.eval(
    `(() => { const r = document.getElementById("fr").getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
  );
  const { menu, at } = await openMenu(page, frame, offset, "admin", { menuIn: page, menuOffset: { x: 0, y: 0 } });
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "毛玻璃下的同站 iframe：菜单可用");
  assert.equal(await menu.eval(`!!document.querySelector(".banner.warning")`), false, "同站不显示嵌入提示");
  await shot(page, "menu-frame-same");
  await click(page, at.x, at.y);
  await waitFor(async () => JSON.stringify(await values(frame)) === JSON.stringify(filled), "点一次即填入");
  ok("同站 iframe（外层带毛玻璃）：菜单由顶层页面显示，可以使用，不显示嵌入提示，点一次即填入");
}

// 4d. 多层嵌套的 iframe：登录框的父帧不是顶层，菜单在登录框所在的帧中显示，高度不超出它（放不下的内容在菜单内滚动）
{
  const page = await open(`http://127.0.0.1:${PORT}/frame-nested`);
  const target = await waitFor(async () => {
    const { targetInfos } = await browser.send("Target.getTargets");
    return targetInfos.find((t) => t.type === "iframe" && t.url === `${LOCAL}/wrap`);
  }, "外层 iframe");
  const wrap = await attach(browser, target.targetId);
  const frame = await childFrame(wrap, "/login-short");
  await waitFor(() => frame.eval(`document.readyState === "complete" && !!document.getElementById("u")`), "嵌套的登录页加载");
  const outer = await page.eval(`(() => { const r = document.getElementById("fr").getBoundingClientRect(); return { x: r.left, y: r.top }; })()`);
  const inner = await wrap.eval(`(() => { const r = document.getElementById("inner").getBoundingClientRect(); return { x: r.left, y: r.top }; })()`);
  const offset = { x: outer.x + inner.x, y: outer.y + inner.y };
  const { menu } = await openMenu(page, frame, offset);
  // 菜单报告高度之后才会收缩到可用的空间
  await sleep(300);
  const box = await frame.eval(
    `(() => { const r = [...document.querySelectorAll("div[popover]")].at(-1).getBoundingClientRect(); return { top: r.top, bottom: r.bottom, height: innerHeight }; })()`,
  );
  assert.ok(box.top >= 0 && box.bottom <= box.height, `菜单超出了 iframe：${JSON.stringify(box)}`);
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "嵌套的 iframe 中菜单可用");
  await shot(page, "menu-frame-nested");
  ok("多层嵌套的 iframe：菜单在登录框所在的帧中显示，不超出 iframe，完整可见后可以使用");
}

// 6. 保存与更新（协议 v2）：提交后的页面顶部出现保存栏（扩展源 iframe，同样的点击劫持防护）

/** 保存栏（等它出现并可用），返回按钮在页面中的位置。 */
async function saveBar(page) {
  const target = await waitFor(async () => {
    const { targetInfos } = await browser.send("Target.getTargets");
    return targetInfos.find((t) => t.type === "iframe" && t.url.endsWith("/bar.html") && !used.has(t.targetId));
  }, "保存栏");
  used.add(target.targetId);
  const bar = await attach(browser, target.targetId);
  await waitFor(() => bar.eval(`document.body.classList.contains("armed") && !!document.querySelector("button")`), "保存栏可用");
  const host = await page.eval(
    `(() => { const r = [...document.querySelectorAll("div[popover]")].at(-1).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`,
  );
  const button = async (text) => {
    const r = await bar.eval(
      `(() => { const b = [...document.querySelectorAll("button")].find((b) => b.textContent === ${JSON.stringify(text)}); const r = b.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`,
    );
    return { x: host.x + r.x, y: host.y + r.y };
  };
  return { bar, button };
}

/** 填写并用可信点击提交表单，等跳转完成。 */
async function submit(page, values) {
  await page.eval(`(() => { for (const [id, v] of Object.entries(${JSON.stringify(values)})) { const el = document.getElementById(id); el.focus(); el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); } })()`);
  const go = await page.eval(`(() => { const r = document.getElementById("go").getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
  await click(page, go.x, go.y);
  await waitFor(() => page.eval(`location.pathname === "/done" && document.readyState === "complete"`), "提交后跳转");
}

const noBar = async (what) => {
  await sleep(1500);
  const { targetInfos } = await browser.send("Target.getTargets");
  assert.equal(targetInfos.some((t) => t.url.endsWith("/bar.html") && !used.has(t.targetId)), false, what);
};

/** 经弹窗页（当前标签页是 page）查询这个网站的候选与某个条目的密码。 */
async function lookup(username) {
  return popup.eval(`(async () => {
    const c = await chrome.runtime.sendMessage({ type: "candidates" });
    const item = c.candidates.find((x) => x.subtitle === ${JSON.stringify(username)});
    if (!item) return null;
    const s = await chrome.runtime.sendMessage({ type: "secret", itemId: item.item_id });
    return { title: item.title, password: s.secret?.password };
  })()`);
}

{
  // 新登录：提示保存
  const page = await open(`${LOCAL}/post`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "登录页加载");
  await submit(page, { u: "newuser", p: "fresh-pass" });
  const { bar, button } = await saveBar(page);
  assert.match(await bar.eval(`document.body.innerText`), new RegExp(`保存这个登录到 Keevo？[\\s\\S]*localhost:${PORT} · newuser`));
  await shot(page, "save-bar");
  const save = await button("保存");
  await click(page, save.x, save.y);
  await waitFor(() => bar.eval(`document.body.innerText.includes("已保存到 Keevo")`), "保存成功");
  assert.deepEqual(await lookup("newuser"), { title: `localhost:${PORT}`, password: "fresh-pass" });
  ok("提交新的登录后，跳转后的页面出现保存栏；可信点击保存后，Keevo 中有这条登录");
}

{
  // 由 Keevo 填入、没有改动就提交：不提示
  const page = await open(`${LOCAL}/post`);
  const { menu, at } = await openMenu(page);
  await waitFor(() => menu.eval(`document.body.classList.contains("armed")`), "菜单可用");
  await click(page, at.x, at.y);
  await waitFor(async () => JSON.stringify(await values(page)) === JSON.stringify(filled), "填入");
  await submit(page, {});
  await noBar("Keevo 填入的密码没有改动：不提示保存");
  // 普通登录表单、同一用户名、不同密码：扩展无从知道密码是否改过，不提示更新
  const again = await open(`${LOCAL}/post`);
  await waitFor(() => again.eval(`document.readyState === "complete"`), "登录页加载");
  await submit(again, { u: "admin", p: "typed-by-hand" });
  await noBar("普通登录表单不提示更新");
  ok("Keevo 填入后直接提交、普通登录表单上的已有用户名：都不出现保存栏");
}

{
  // 修改密码的表单：提示更新，Keevo 确认（开发服务自动确认）后生效
  const page = await open(`${LOCAL}/change`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "修改密码页加载");
  await submit(page, { cur: "demo-local-password", p: "rotated-pass", p2: "rotated-pass" });
  const { bar, button } = await saveBar(page);
  assert.match(await bar.eval(`document.body.innerText`), /更新 Keevo 中「本地开发（演示）」的密码？/);
  await shot(page, "update-bar");
  const update = await button("更新");
  await click(page, update.x, update.y);
  await waitFor(() => bar.eval(`document.body.innerText.includes("密码已更新")`), "更新成功");
  assert.equal((await lookup("admin")).password, "rotated-pass");
  ok("修改密码的表单提示更新；确认后 Keevo 中的密码随之更新");
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
  // 前面的更新测试已把演示条目的密码改为 rotated-pass
  assert.deepEqual(await values(page), ["admin", "rotated-pass"]);
  ok("弹窗填充经内容脚本填入当前标签页的登录表单（得到更新后的密码）");
}

// 5b. 弹窗填充：顶层没有登录表单时，填入同站 iframe 中的登录表单（按 iframe 的网址列出条目）；跨站的 iframe 不从弹窗填充
{
  const page = await open(`${SAME_SITE_TOP}/frame-same`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "同站嵌入页加载");
  const frame = await childFrame(page, `localhost:${PORT}/login`);
  await waitFor(() => frame.eval(`document.readyState === "complete" && !!document.getElementById("u")`), "同站嵌入的登录页加载");
  const result = await popup.eval(`(async () => {
    const c = await chrome.runtime.sendMessage({ type: "candidates" });
    const item = c.candidates.find((x) => x.title === "本地开发（演示）");
    if (!item) return { origin: c.origin };
    const r = await chrome.runtime.sendMessage({ type: "fill", itemId: item.item_id });
    return { origin: c.origin, fill: r.fill };
  })()`);
  assert.deepEqual(result, { origin: `https://localhost:${PORT}`, fill: "filled" });
  assert.deepEqual(await values(frame), ["admin", "rotated-pass"]);
  const cross = await open(`http://127.0.0.1:${PORT}/frame`);
  await waitFor(() => cross.eval(`document.readyState === "complete"`), "跨站嵌入页加载");
  const crossOrigin = await popup.eval(`chrome.runtime.sendMessage({ type: "candidates" }).then((c) => c.origin)`);
  assert.equal(crossOrigin, `http://127.0.0.1:${PORT}`, "跨站 iframe：弹窗仍按顶层网址列出条目");
  ok("弹窗填充：顶层没有登录表单时填入同站 iframe（按它的网址列出条目），跨站 iframe 不从弹窗填充");
}

// 7. 弹窗的补充功能（设计稿"扩展 · 弹窗：搜索、生成密码、新建登录与解锁"）
const send = (msg) => popup.eval(`chrome.runtime.sendMessage(${JSON.stringify(msg)})`);
{
  const page = await open(`${LOCAL}/login`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "登录页加载");
  assert.equal((await send({ type: "state" })).version, 3, "与开发服务协商出协议 v3");

  // 搜索全部条目：输入时不打扰用户；点了"在全部条目中搜索"才请 Keevo 允许（开发服务自动允许），之后直接返回
  assert.equal((await send({ type: "search", query: "github", ask: false })).error, "not_authorized");
  assert.equal(serviceLog.includes("已自动允许搜索"), false);
  const allowed = await send({ type: "search", query: "github", ask: true });
  assert.deepEqual(allowed.results.map((c) => c.title), ["GitHub（演示）"]);
  assert.match(serviceLog, /已自动允许搜索「github」/);
  const again = await send({ type: "search", query: "演示", ask: false });
  assert.deepEqual(again.results.map((c) => c.title).sort(), ["Example（演示）", "GitHub（演示）", "本地开发（演示）"].sort());
  ok("搜索全部条目：没有允许时输入不弹确认；允许一次后，这次解锁中直接返回标题与用户名");

  // 在 Keevo 中打开：条目核对存在后转给 Keevo；不存在的条目被拒
  const gh = allowed.results[0].item_id;
  assert.equal((await send({ type: "open", itemId: gh })).error, undefined);
  await waitFor(async () => serviceLog.includes(`请求打开条目 ${gh}`), "Keevo 收到打开请求");
  assert.equal((await send({ type: "open", itemId: "00".repeat(16) })).error, "not_found");
  assert.equal((await send({ type: "unlock" })).error, undefined);
  assert.equal(serviceLog.includes("请求解锁"), false, "已解锁时不打扰 Keevo");
  ok("在 Keevo 中打开：转给 Keevo 选中条目，不存在的条目被拒；已解锁时请求解锁不打扰 Keevo");

  // 生成密码：与 Keevo.app 同一份实现（WASM），按设置生成
  const pw = await send({ type: "generate", recipe: { kind: "password", length: 24, digits: true, symbols: false } });
  assert.equal([...pw.generated.value].length, 24);
  assert.match(pw.generated.value, /^[A-Za-z0-9]+$/);
  assert.ok(pw.generated.entropy > 120, `熵 ${pw.generated.entropy}`);
  const phrase = await send({ type: "generate", recipe: { kind: "passphrase", words: 4, capitalize: false, number: false } });
  assert.equal(phrase.generated.value.split("-").length, 4);
  ok("生成密码：随机字符与口令短语都按设置生成，并给出熵");
}

{
  // 填入网页：填到注册表单的新密码框（密码与确认），提交后照常询问保存
  const page = await open(`${LOCAL}/signup`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "注册页加载");
  const { generated } = await send({ type: "generate", recipe: { kind: "password", length: 20, digits: true, symbols: true } });
  assert.equal((await send({ type: "fill_generated", password: generated.value })).fill, "filled");
  assert.deepEqual(await page.eval(`[document.getElementById("p").value, document.getElementById("p2").value]`), [generated.value, generated.value]);
  await submit(page, { u: "signup-user" });
  const { bar } = await saveBar(page);
  assert.match(await bar.eval(`document.body.innerText`), /保存这个登录到 Keevo？[\s\S]*signup-user/);
  ok("生成的密码填入注册表单的新密码框（含确认框）；提交后出现保存栏");
}

{
  // 新建登录：保存到 Keevo（v2 save），只保存网站地址，之后作为当前网站的候选
  const page = await open(`${LOCAL}/post`);
  await waitFor(() => page.eval(`document.readyState === "complete"`), "登录页加载");
  const r = await send({ type: "save_login", username: "popup-user", password: "popup-pass" });
  assert.ok(r.saved, JSON.stringify(r));
  assert.deepEqual(await lookup("popup-user"), { title: `localhost:${PORT}`, password: "popup-pass" });
  ok("新建登录：保存到 Keevo，标题为主机名，之后可以直接填充");

  // 弹窗界面：搜索框搜索全部条目，其他网站的条目只能在 Keevo 中打开；底部入口与生成密码页
  // 先在旧文档上做标记：reload 是异步的，否则可能在旧文档里看到搜索框
  await popup.eval(`window.__beforeReload = true; location.reload()`);
  await waitFor(() => popup.eval(`!window.__beforeReload && !!document.getElementById("search")`), "弹窗列表");
  await popup.eval(`(() => { const s = document.getElementById("search"); s.value = "演示"; s.dispatchEvent(new Event("input")); })()`);
  await waitFor(
    () => popup.eval(`[...document.querySelectorAll(".others .title")].map((e) => e.textContent).includes("GitHub（演示）")`),
    "其他网站的搜索结果",
  );
  const ui = await popup.eval(`({
    others: [...document.querySelectorAll(".others button.open")].map((b) => b.getAttribute("aria-label")),
    links: [...document.querySelectorAll(".links button")].map((b) => b.textContent),
    placeholder: document.getElementById("search").placeholder,
  })`);
  assert.ok(ui.others.includes("在 Keevo 中打开 GitHub（演示）"), JSON.stringify(ui));
  assert.deepEqual(ui.links, ["生成密码", "新建登录", "在 Keevo 中打开"]);
  assert.equal(ui.placeholder, "搜索全部条目");
  // 截图需要弹窗页在前台（之后的操作不再依赖"当前标签页"）
  if (process.env.KEEVO_SHOTS) {
    const { targetInfos } = await browser.send("Target.getTargets");
    const t = targetInfos.find((x) => x.url.endsWith("/popup.html"));
    await browser.send("Target.activateTarget", { targetId: t.targetId });
  }
  await shot(popup, "popup-search");
  await popup.eval(`[...document.querySelectorAll(".links button")].find((b) => b.textContent === "生成密码").click()`);
  await waitFor(() => popup.eval(`!!document.querySelector(".gen-value output .classified")`), "生成密码页");
  const gen = await popup.eval(`({ title: document.querySelector("header h1").textContent, meter: document.querySelector(".meter").getAttribute("aria-label") })`);
  assert.equal(gen.title, "生成密码");
  assert.match(gen.meter, /^强度：.+，约 \d+ 比特熵$/);
  await shot(popup, "popup-generator");
  await popup.eval(`document.querySelector("header button").click()`);
  await popup.eval(`[...document.querySelectorAll(".links button")].find((b) => b.textContent === "新建登录").click()`);
  await waitFor(() => popup.eval(`document.getElementById("nl-password")?.value.length === 20`), "新建登录页（已生成密码）");
  await shot(popup, "popup-new-login");
  ok("弹窗界面：搜索结果分为当前网站与其他网站，底部入口、生成密码页与新建登录页按设计稿显示");
}

console.log(`全部通过（${checks} 项）`);
await cleanup();
process.exit(0);
