// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 真实网站登录页快照的采集（docs/roadmap.md §8 第 2 项）。
//
// 用法：node apps/browser-extension/test/capture-sites.mjs [--headful] [网站 id …]
//
// - 网站清单、采集步骤与预期在 sites/sites.json。快照只保存在本机（sites/snapshots/，git 忽略）：
//   - site-<id>.html：渲染后的完整 DOM。去掉脚本、事件处理属性、隐藏字段的值与外部资源的预加载，样式表内联，
//     开放的 shadow root 序列化为声明式 shadow DOM；
//   - site-<id>.png：截图；
//   - site-<id>.fields.json：页面中各输入框的摘要（选择器、类型、提示文字、是否可见），用来写预期。
// - 每个网站用全新的浏览器上下文：没有 cookie、没有登录。不输入、不提交任何内容，只按 steps 点击"密码登录"
//   一类的选项卡。登录表单在 iframe 中时，frame 指定 iframe 地址的片段：默认单独打开这个 iframe 的页面；
//   frameMode 为 inplace 时在原页面中就地读取（iframe 依赖外层页面、单独打开是空白时）。
// - 无头模式下 User-Agent 改为普通 Chrome（有的网站拒绝 HeadlessChrome）；被人机验证拦下时可以用 --headful。

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { attach, click, findChromium, launchChrome, NO_CHROMIUM, waitFor } from "./cdp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const SITES = join(here, "sites");
const OUT = join(SITES, "snapshots");
const CHROME = findChromium();
if (!CHROME) {
  console.error(NO_CHROMIUM);
  process.exit(1);
}
const argv = process.argv.slice(2);
const headful = argv.includes("--headful");
const only = new Set(argv.filter((a) => !a.startsWith("--")));
const { sites } = JSON.parse(readFileSync(join(SITES, "sites.json"), "utf8"));
const selected = sites.filter((s) => only.size === 0 || only.has(s.id));
if (selected.length === 0) {
  console.error(`没有匹配的网站：${[...only].join("、")}`);
  process.exit(1);
}
mkdirSync(OUT, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dir = mkdtempSync(join(tmpdir(), "kvcapture"));
const browser = await launchChrome(CHROME, [
  ...(headful ? [] : ["--headless=new"]),
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  `--user-data-dir=${join(dir, "profile")}`,
  "--window-size=1280,900",
  // 不暴露 navigator.webdriver：有的网站因此直接给出人机验证
  "--disable-blink-features=AutomationControlled",
  "about:blank",
]);
const { userAgent } = await browser.send("Browser.getVersion");
const UA = userAgent.replace("HeadlessChrome", "Chrome");

/** 在页面中运行：收集文档与全部开放 shadow root 中的输入框，给出能在快照中复现的选择器。 */
const FIELDS = `(() => {
  const unique = (root, sel) => { try { return root.querySelectorAll(sel).length === 1; } catch { return false; } };
  const local = (el) => {
    const root = el.getRootNode();
    const tag = el.localName;
    if (el.id && unique(root, "#" + CSS.escape(el.id))) return "#" + CSS.escape(el.id);
    for (const attr of ["name", "autocomplete", "type", "placeholder", "aria-label", "data-testid"]) {
      const v = el.getAttribute(attr);
      if (v) {
        const sel = tag + "[" + attr + "=" + JSON.stringify(v) + "]";
        if (unique(root, sel)) return sel;
      }
    }
    const path = [];
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const parent = e.parentElement;
      const same = parent ? [...parent.children].filter((c) => c.localName === e.localName) : [e];
      path.unshift(e.localName + (same.length > 1 ? ":nth-of-type(" + (same.indexOf(e) + 1) + ")" : ""));
      if (e.id && unique(root, "#" + CSS.escape(e.id))) { path[0] = "#" + CSS.escape(e.id); break; }
    }
    return path.join(" > ");
  };
  const selector = (el) => {
    const parts = [];
    for (let e = el; e; ) {
      parts.unshift(local(e));
      const root = e.getRootNode();
      e = root instanceof ShadowRoot ? root.host : null;
    }
    return parts.join(" >>> ");
  };
  const out = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) walk(el.shadowRoot);
      if (!["input", "textarea", "select"].includes(el.localName)) continue;
      const type = (el.getAttribute("type") || (el.localName === "input" ? "text" : el.localName)).toLowerCase();
      if (["submit", "button", "image", "reset", "file", "range", "color"].includes(type)) continue;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      const labelledby = (el.getAttribute("aria-labelledby") || "").split(/\\s+/).filter(Boolean)
        .map((id) => el.getRootNode().getElementById?.(id)?.textContent?.trim()).filter(Boolean).join(" ");
      out.push({
        selector: selector(el),
        type,
        name: el.getAttribute("name") || undefined,
        id: el.id || undefined,
        autocomplete: el.getAttribute("autocomplete") || undefined,
        placeholder: el.getAttribute("placeholder") || undefined,
        label: [...(el.labels || [])].map((l) => l.textContent.trim()).join(" ") || el.getAttribute("aria-label") || labelledby || undefined,
        visible: r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0,
        rect: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)],
        disabled: el.disabled || undefined,
        readonly: el.readOnly || undefined,
      });
    }
  };
  walk(document);
  return { url: location.href, title: document.title, fields: out };
})()`;

/** 在页面中运行：内联样式表、去掉脚本与可执行的内容，序列化为 HTML（含声明式 shadow DOM）。 */
const SERIALIZE = (sheets, source) => `(() => {
  const sheets = ${JSON.stringify(sheets)};
  const roots = [];
  const walk = (root) => { for (const el of root.querySelectorAll("*")) if (el.shadowRoot) { roots.push(el.shadowRoot); walk(el.shadowRoot); } };
  walk(document);
  const all = [document, ...roots];
  const style = (text, media) => { const s = document.createElement("style"); if (media) s.media = media; s.textContent = text; return s; };
  for (const root of all) {
    for (const link of root.querySelectorAll('link[rel~="stylesheet"]')) {
      if (sheets[link.href] !== undefined && !link.disabled) link.replaceWith(style(sheets[link.href], link.media));
      else link.remove();
    }
    // 构造的样式表（adoptedStyleSheets）不会被序列化，改为 <style>
    const adopted = [...(root.adoptedStyleSheets || [])].map((s) => { try { return [...s.cssRules].map((r) => r.cssText).join("\\n"); } catch { return ""; } }).join("\\n");
    if (adopted) (root === document ? document.head || document.documentElement : root).prepend(style(adopted));
    for (const el of root.querySelectorAll("script, noscript, link, meta[http-equiv], base, object, embed, portal")) el.remove();
    for (const el of root.querySelectorAll("*")) {
      for (const a of [...el.attributes]) {
        const n = a.name.toLowerCase();
        if (n.startsWith("on") || n === "nonce" || n === "integrity") el.removeAttribute(a.name);
        else if (/^\\s*javascript:/i.test(a.value)) el.setAttribute(a.name, "#");
      }
      if (el.localName === "iframe") { el.removeAttribute("srcdoc"); el.setAttribute("src", "about:blank"); }
      if (el.localName === "input" && (el.getAttribute("type") || "").toLowerCase() === "hidden") el.setAttribute("value", "");
    }
  }
  const html = document.documentElement;
  const attrs = [...html.attributes].map((a) => " " + a.name + '="' + a.value.replace(/&/g, "&amp;").replace(/"/g, "&quot;") + '"').join("");
  const head = '<meta charset="utf-8"><!-- Keevo 登录页快照（只保存在本机，不提交）：' + ${JSON.stringify(source)}.replace(/--/g, "- -") + " -->";
  // 有的网站用 shadow DOM 的模拟实现（如 Salesforce 的 synthetic shadow），el.shadowRoot 不是真正的 ShadowRoot
  let body;
  try {
    body = html.getHTML({ serializableShadowRoots: true, shadowRoots: roots });
  } catch {
    const real = roots.filter((r) => { try { document.createElement("div").getHTML({ shadowRoots: [r] }); return true; } catch { return false; } });
    body = html.getHTML({ serializableShadowRoots: true, shadowRoots: real });
  }
  return "<!doctype html>\\n<html" + attrs + ">" + head + body + "</html>\\n";
})()`;

/** 点击可见的、文字恰好为 text 的最小元素（或匹配选择器的元素）的中心。 */
const TARGET = (step) => `(() => {
  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden"; };
  let el = null;
  if (${JSON.stringify(step.click ?? null)}) el = document.querySelector(${JSON.stringify(step.click ?? "")});
  else {
    const text = ${JSON.stringify(step.text ?? "")};
    const hits = [...document.querySelectorAll("body *")].filter((e) => e.textContent.trim() === text && visible(e));
    el = hits.find((e) => ![...e.children].some((c) => hits.includes(c))) ?? null;
  }
  if (!el || !visible(el)) return null;
  el.scrollIntoView({ block: "center" });
  const r = el.getBoundingClientRect();
  return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
})()`;

async function capture(site) {
  const { browserContextId } = await browser.send("Target.createBrowserContext", { disposeOnDetach: true });
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank", browserContextId });
  const page = await attach(browser, targetId);
  const sheets = new Map();
  const off = browser.on((msg) => {
    if (msg.sessionId !== page.id) return;
    if (msg.method === "CSS.styleSheetAdded") sheets.set(msg.params.header.styleSheetId, msg.params.header);
    if (msg.method === "CSS.styleSheetRemoved") sheets.delete(msg.params.styleSheetId);
  });
  try {
    const lang = site.group === "cn" ? "zh-CN" : "en-US";
    await page.send("Network.enable");
    await page.send("Network.setUserAgentOverride", { userAgent: UA, acceptLanguage: `${lang},${lang.slice(0, 2)};q=0.9` });
    await page.send("Emulation.setLocaleOverride", { locale: lang }).catch(() => undefined);
    await page.send("Page.enable");
    await page.send("DOM.enable");
    await page.send("CSS.enable");
    await page.send("Emulation.setFocusEmulationEnabled", { enabled: true });

    const settle = async (url) => {
      if (url) await page.send("Page.navigate", { url });
      await waitFor(() => page.eval(`document.readyState === "complete"`), "页面加载", 30000).catch(() => undefined);
      // 等到出现可见的输入框（单页应用渲染较晚），最多 15 秒
      await waitFor(() => page.eval(`${FIELDS}.fields.some((f) => f.visible)`), "输入框", 15000).catch(() => undefined);
      await sleep(1500);
    };
    await settle(site.url);
    // 在哪个文档中读取：默认是页面本身；frameMode 为 inplace 时是页面中的 iframe（同站、同一进程）
    let context;
    const evaluate = async (expression) => {
      if (context === undefined) return page.eval(expression);
      const r = await page.send("Runtime.evaluate", { expression, contextId: context, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(`iframe 中的脚本出错：${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    let cssFrame = (await page.send("Page.getFrameTree")).frameTree.frame.id;
    if (site.frame) {
      const { frameTree } = await page.send("Page.getFrameTree");
      const find = (t) => (t.frame.url.includes(site.frame) ? t.frame : (t.childFrames ?? []).map(find).find(Boolean));
      const frame = find(frameTree);
      if (!frame) throw new Error(`没有找到地址包含 ${site.frame} 的 iframe`);
      if (site.frameMode === "inplace") {
        // 有的 iframe 依赖外层页面发来的消息，单独打开是空白的：就地读取（隔离环境与页面共用同一个 DOM）
        if (site.steps?.length) throw new Error("就地读取 iframe 时不支持点击步骤");
        context = (await page.send("Page.createIsolatedWorld", { frameId: frame.id, worldName: "keevo-capture" })).executionContextId;
        cssFrame = frame.id;
        await waitFor(() => evaluate(`${FIELDS}.fields.some((f) => f.visible)`), "iframe 中的输入框", 15000).catch(() => undefined);
        await sleep(1500);
      } else {
        sheets.clear();
        await settle(frame.url);
        cssFrame = (await page.send("Page.getFrameTree")).frameTree.frame.id;
      }
    }
    for (const step of site.steps ?? []) {
      if (step.wait) {
        await sleep(step.wait);
        continue;
      }
      const at = await waitFor(() => page.eval(TARGET(step)), `可点击的 ${step.click ?? step.text}`, 10000);
      await click(page, at.x, at.y);
      await sleep(2000);
    }
    const fields = await evaluate(FIELDS);
    const { frameTree } = await page.send("Page.getFrameTree");
    const frames = [];
    const collect = (t) => {
      for (const c of t.childFrames ?? []) {
        if (/^https?:/.test(c.frame.url)) frames.push(c.frame.url);
        collect(c);
      }
    };
    collect(frameTree);
    fields.frames = frames;
    const texts = {};
    for (const h of sheets.values()) {
      if (h.frameId !== cssFrame || h.isInline || h.isConstructed || !h.sourceURL) continue;
      try {
        texts[h.sourceURL] = (await page.send("CSS.getStyleSheetText", { styleSheetId: h.styleSheetId })).text;
      } catch {
        // 已经被移除的样式表
      }
    }
    const shot = await page.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(OUT, `site-${site.id}.png`), Buffer.from(shot.data, "base64"));
    const html = await evaluate(SERIALIZE(texts, `${fields.url}，${new Date().toISOString().slice(0, 10)}`));
    writeFileSync(join(OUT, `site-${site.id}.html`), html);
    writeFileSync(join(OUT, `site-${site.id}.fields.json`), `${JSON.stringify({ captured: new Date().toISOString(), ...fields }, null, 1)}\n`);
    const visible = fields.fields.filter((f) => f.visible);
    return `${visible.length} 个可见输入框（${visible.map((f) => f.type).join("、") || "无"}），${Math.round(html.length / 1024)} KiB，${fields.url}`;
  } finally {
    off();
    await browser.send("Target.disposeBrowserContext", { browserContextId }).catch(() => undefined);
  }
}

let failed = 0;
try {
  console.log(`采集 ${selected.length} 个网站的登录页（${headful ? "有界面" : "无头"} Chrome）`);
  for (const site of selected) {
    try {
      const summary = await Promise.race([
        capture(site),
        sleep(90000).then(() => {
          throw new Error("超过 90 秒");
        }),
      ]);
      console.log(`  ✓ ${site.id}：${summary}`);
    } catch (e) {
      failed += 1;
      console.log(`  ✗ ${site.id}：${e.message}`);
    }
  }
} finally {
  await browser.close();
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch {
    // Chrome 的辅助进程可能还在写配置目录
  }
}
console.log(failed ? `${failed} 个网站没有采集成功` : "全部采集成功");
console.log(`快照在 ${OUT}（只保存在本机）`);
process.exit(existsSync(OUT) && failed === 0 ? 0 : 1);
