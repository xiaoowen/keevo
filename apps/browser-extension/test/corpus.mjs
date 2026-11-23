// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 自动填充回归语料库：在真实的无头 Chrome 中逐页检查内容脚本的字段识别与填充（test/corpus/*.html）。
//
// - 每个页面在 <script type="application/json" id="keevo-expect"> 中写明预期：
//   icons：聚焦各字段后应出现的图标类别（login、otp；null 为不出现）；
//   fills：从某个字段的菜单（anchor）或从弹窗（anchor 为 null）填充后，各字段的值。
// - 图标在封闭的 shadow root 中，页面读不到；这里经 DevTools 协议（DOM.getDocument pierce）读出它的无障碍标签。
// - 填充由扩展的 Service Worker 直接发给内容脚本，与菜单、弹窗走同一条路径，但不需要 Keevo 与配对。
//
// 选择器中的 " >>> " 表示进入开放的 shadow root；"#id[attr]" 表示读取属性而不是值。
// 由 scripts/build-extension.sh --test 调用；没有 Chrome 时跳过。
//
// 真实网站的登录页快照（test/sites/，只保存在本机）存在时一并检查，预期写在 sites/sites.json 中。合成页面必须
// 全部通过；真实网站按页面计算识别率，不低于 95% 才算通过（docs/roadmap.md §8）。测试用的 Chrome 解析不了
// localhost 以外的任何域名，快照不会访问真实网站。
//
// 用法：node corpus.mjs [--record] [文件名片段…]
//   --record：把真实网站的结果写入 sites/results.md；文件名片段：只检查文件名包含其中之一的页面（如 site-）。

import assert from "node:assert/strict";
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { attach, findChromium, launchChrome, NO_CHROMIUM, waitFor } from "./cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CHROME = findChromium();
const EXT_ID = "boojggkmhkakoacccigoiibnlkffcpof";
if (!CHROME) {
  console.log(`${NO_CHROMIUM}，跳过自动填充语料测试`);
  process.exit(0);
}
const CORPUS = join(here, "corpus");
const SNAPSHOTS = join(here, "sites", "snapshots");
const argv = process.argv.slice(2);
const record = argv.includes("--record");
const filters = argv.filter((a) => !a.startsWith("--"));
const SITE_PASS_RATE = 0.95;
const VALUES = { $U: "corpus-user", $P: "corpus-pass", $T: "123456" };
const LABELS = { "用 Keevo 填充": "login", "用 Keevo 填入一次性密码": "otp" };

const dir = mkdtempSync(join(tmpdir(), "kvcorpus"));
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

const server = createServer((req, res) => {
  const name = new URL(req.url, "http://x").pathname.slice(1);
  const file = join(name.startsWith("site-") ? SNAPSHOTS : CORPUS, name);
  if (!/^[\w-]+\.html$/.test(name) || !existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
cleanups.push(() => new Promise((r) => server.close(r)));
const BASE = `http://localhost:${server.address().port}`;

// 测试用的扩展副本：网站权限改为安装时授予，内容脚本随即注册到所有网站
const ext = join(dir, "ext");
cpSync(join(here, "..", "dist"), ext, { recursive: true });
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
manifest.host_permissions = manifest.optional_host_permissions;
writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));

const browser = await launchChrome(CHROME, [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  `--user-data-dir=${join(dir, "profile")}`,
  "--window-size=1200,900",
  // 快照中残留的外部地址一律解析失败：测试不访问真实网站
  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost",
  "about:blank",
]);
cleanups.push(() => browser.close());

try {
  const { id } = await browser.send("Extensions.loadUnpacked", { path: ext });
  assert.equal(id, EXT_ID);
  const sw = await attach(
    browser,
    (
      await waitFor(async () => {
        const { targetInfos } = await browser.send("Target.getTargets");
        return targetInfos.find((t) => t.type === "service_worker" && t.url.startsWith(`chrome-extension://${EXT_ID}/`));
      }, "扩展的 Service Worker")
    ).targetId,
  );
  // 内容脚本注册完成（Service Worker 启动时按权限注册）
  await waitFor(
    () => sw.eval(`chrome.scripting.getRegisteredContentScripts().then((s) => s.length > 0)`),
    "内容脚本注册",
  );

  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank" });
  const page = await attach(browser, targetId);
  await browser.send("Target.activateTarget", { targetId });
  await page.send("Emulation.setFocusEmulationEnabled", { enabled: true });
  await page.send("DOM.enable");

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const resolve = (sel) =>
    `${JSON.stringify(sel)}.split(" >>> ").reduce((root, part, i) => (i === 0 ? document : root?.shadowRoot)?.querySelector(part), null)`;

  async function load(url) {
    await page.send("Page.navigate", { url });
    await waitFor(() => page.eval(`location.href === ${JSON.stringify(url)} && document.readyState === "complete"`), url, 20000);
    // 真实网站的快照很大，内容脚本扫描需要更久
    await sleep(url.includes("/site-") ? 800 : 150);
  }

  /** 当前显示的 Keevo 图标的类别（读封闭 shadow root 中按钮的无障碍标签）。 */
  async function iconKind() {
    const { root } = await page.send("DOM.getDocument", { depth: -1, pierce: true });
    let found = null;
    const walk = (node) => {
      if (node.nodeName === "BUTTON" && node.attributes) {
        const i = node.attributes.indexOf("aria-label");
        if (i >= 0 && LABELS[node.attributes[i + 1]]) found = LABELS[node.attributes[i + 1]];
      }
      for (const c of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(c);
    };
    walk(root);
    return found;
  }

  async function focus(sel) {
    await page.eval(`(() => { let a = document.activeElement; while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement; a?.blur?.(); })()`);
    await sleep(250);
    await page.eval(`${resolve(sel)}.focus()`);
    await sleep(250);
  }

  async function read(key) {
    const m = /^(.*)\[([\w-]+)\]$/.exec(key);
    const sel = m ? m[1] : key;
    const expr = m ? `(${resolve(sel)})?.getAttribute(${JSON.stringify(m[2])}) ?? ""` : `(${resolve(sel)})?.value ?? null`;
    return page.eval(expr);
  }

  const pages = readdirSync(CORPUS)
    .filter((f) => f.endsWith(".html"))
    .sort()
    .map((file) => {
      const html = readFileSync(join(CORPUS, file), "utf8");
      return { file, real: false, expect: JSON.parse(/<script type="application\/json" id="keevo-expect">([\s\S]*?)<\/script>/.exec(html)[1]) };
    });
  const { sites } = JSON.parse(readFileSync(join(here, "sites", "sites.json"), "utf8"));
  const pending = [];
  for (const site of sites) {
    if (site.excluded) continue;
    const file = `site-${site.id}.html`;
    if (!existsSync(join(SNAPSHOTS, file)) || !site.expect) {
      pending.push(site.id);
      continue;
    }
    pages.push({ file, real: true, site, expect: { title: site.name, ...site.expect } });
  }
  const selected = pages.filter((p) => filters.length === 0 || filters.some((f) => p.file.includes(f)));
  const synthetic = selected.filter((p) => !p.real).length;
  const real = selected.length - synthetic;
  const tally = { true: { pass: 0, total: 0 }, false: { pass: 0, total: 0 } };
  const failures = [];
  const results = [];
  let iconTotal = 0;
  let iconOk = 0;
  let fillTotal = 0;
  let fillOk = 0;
  console.log(`自动填充回归语料（${synthetic} 个合成页面、${real} 个真实网站快照，真实 Chrome）`);
  if (pending.length && filters.length === 0) {
    console.log(`  · ${pending.length} 个网站没有快照或预期，未检查（快照只在本机，用 capture-sites.mjs 采集）`);
  }
  for (const { file, real: isReal, site, expect } of selected) {
    const url = `${BASE}/${file}`;
    const problems = [];
    try {
      await load(url);
      for (const [sel, kind] of Object.entries(expect.icons)) {
        iconTotal += 1;
        await focus(sel);
        const got = await iconKind();
        if (got === kind) iconOk += 1;
        else problems.push(`聚焦 ${sel}：图标应为 ${kind}，实际 ${got}`);
      }
      for (const step of expect.fills) {
        fillTotal += 1;
        await load(url);
        if (step.anchor) await focus(step.anchor);
        const outcome = await sw.eval(`(async () => {
          const [tab] = await chrome.tabs.query({ url: ${JSON.stringify(url)} });
          return chrome.tabs.sendMessage(tab.id, {
            type: "fill", origin: ${JSON.stringify(new URL(url).origin)},
            username: ${JSON.stringify(VALUES.$U)}, password: ${JSON.stringify(VALUES.$P)}, totp: ${JSON.stringify(VALUES.$T)},
            anchored: ${step.anchor ? "true" : "false"}, kind: ${JSON.stringify(step.kind ?? "login")},
          }, { frameId: 0 });
        })()`);
        const wrong = [];
        if (outcome !== (step.outcome ?? "filled")) wrong.push(`结果应为 ${step.outcome ?? "filled"}，实际 ${outcome}`);
        for (const [key, want] of Object.entries(step.expect)) {
          const value = VALUES[want] ?? want;
          const got = await read(key);
          if (got !== value) wrong.push(`${key} 应为 ${JSON.stringify(value)}，实际 ${JSON.stringify(got)}`);
        }
        if (wrong.length === 0) fillOk += 1;
        else problems.push(`从${step.anchor ? ` ${step.anchor} 的菜单` : "弹窗"}填充：${wrong.join("；")}`);
      }
    } catch (e) {
      problems.push(`出错：${e.message.split("\n")[0]}`);
    }
    tally[isReal].total += 1;
    if (problems.length === 0) tally[isReal].pass += 1;
    else failures.push(file);
    if (isReal) results.push({ site, problems });
    console.log(`  ${problems.length === 0 ? "✓" : "✗"} ${file.replace(/\.html$/, "")}：${expect.title}`);
    for (const p of problems) console.log(`      ${p}`);
  }
  const pct = (a, b) => (b === 0 ? "—" : `${((a / b) * 100).toFixed(1)}%`);
  console.log(`图标识别 ${iconOk}/${iconTotal}（${pct(iconOk, iconTotal)}），填充 ${fillOk}/${fillTotal}（${pct(fillOk, fillTotal)}）`);
  const synth = tally.false;
  const sitesTally = tally.true;
  if (synth.total) console.log(`合成页面 ${synth.pass}/${synth.total}`);
  if (sitesTally.total) {
    console.log(`真实网站识别率 ${sitesTally.pass}/${sitesTally.total}（${pct(sitesTally.pass, sitesTally.total)}，要求 ≥ ${SITE_PASS_RATE * 100}%）`);
  }
  if (record && results.length) writeResults(results, sitesTally);
  const sitesOk = sitesTally.total === 0 || sitesTally.pass / sitesTally.total >= SITE_PASS_RATE;
  if (synth.pass !== synth.total || !sitesOk) {
    console.log(`✗ ${failures.length} 个页面不符合预期${sitesOk ? "（真实网站的识别率达标，合成页面必须全部通过）" : ""}`);
    process.exitCode = 1;
  } else {
    console.log(`全部通过（${selected.length} 个页面${failures.length ? `，真实网站中 ${failures.length} 个不符合预期` : ""}）`);
  }
} finally {
  await cleanup();
}
process.exit(process.exitCode ?? 0);

/** 真实网站的结果写入 sites/results.md（随仓库提交；快照本身不提交）。 */
function writeResults(results, t) {
  const groups = { mainstream: "全球主流", developer: "开发者服务", cn: "国内" };
  const captured = (id) => {
    try {
      return JSON.parse(readFileSync(join(SNAPSHOTS, `site-${id}.fields.json`), "utf8")).captured.slice(0, 10);
    } catch {
      return "—";
    }
  };
  const lines = [
    "# 真实网站登录页的识别结果",
    "",
    `由 \`node apps/browser-extension/test/corpus.mjs --record\` 生成（${new Date().toISOString().slice(0, 10)}）。快照只保存在本机，清单与预期见 [sites.json](sites.json)，说明见 [corpus/README.md](../corpus/README.md)。`,
    "",
    `**识别率 ${t.pass}/${t.total}（${((t.pass / t.total) * 100).toFixed(1)}%）**，要求 ≥ ${SITE_PASS_RATE * 100}%。一个页面上的图标与填充全部符合预期才算识别成功。`,
    "",
    "| 网站 | 分组 | 快照日期 | 结果 |",
    "|---|---|---|---|",
    ...results.map(
      ({ site, problems }) =>
        `| ${site.name} | ${groups[site.group] ?? site.group} | ${captured(site.id)} | ${problems.length ? `✗ ${problems.join("；").replace(/\|/g, "\\|")}${site.note ? `（备注：${site.note}）` : ""}` : "✓"} |`,
    ),
    "",
  ];
  const { sites } = JSON.parse(readFileSync(join(here, "sites", "sites.json"), "utf8"));
  const excluded = sites.filter((s) => s.excluded);
  if (excluded.length) {
    lines.push(
      `**不计入的网站**（${excluded.length} 个，只看能否采集到登录表单，与识别结果无关）：`,
      "",
      ...excluded.map((s) => `- ${s.name}：${s.excluded}`),
      "",
    );
  }
  writeFileSync(join(here, "sites", "results.md"), lines.join("\n"));
  console.log("已写入 sites/results.md");
}
