// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 最小的 Chrome DevTools 协议客户端（管道模式：fd 3 写、fd 4 读，消息以 \0 分隔）。
// 管道模式下可以用 Extensions.loadUnpacked 加载扩展（需要 --enable-unsafe-extension-debugging）；
// 品牌版 Chrome 137 起不再接受 --load-extension 命令行参数。
//
// 浏览器默认用 Playwright 下载的 Chromium（Chrome for Testing，findChromium）。不用 /Applications 中的
// Google Chrome：品牌版 Chrome 在 macOS 上每次启动都会把整个应用复制一份到系统临时目录
// （…/X/com.google.Chrome.code_sign_clone/），进程被强行结束时不会删除，反复运行测试会占满磁盘。
// 关闭浏览器时也先经 DevTools 协议正常退出（close），确实需要品牌版 Chrome 的测试（packaged.mjs）同样不留副本。

import { execFileSync, spawn } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Playwright 下载的 Chromium 的可执行文件；KEEVO_CHROME 可以指定其他浏览器。没有时返回 null（调用方跳过测试）。
 * 安装：npx playwright install chromium（只下载一次，放在 Playwright 的缓存目录中）。
 */
export function findChromium() {
  if (process.env.KEEVO_CHROME) return process.env.KEEVO_CHROME;
  const cache =
    process.env.PLAYWRIGHT_BROWSERS_PATH ??
    (process.platform === "darwin" ? join(homedir(), "Library/Caches/ms-playwright") : join(homedir(), ".cache/ms-playwright"));
  if (!existsSync(cache)) return null;
  const revisions = readdirSync(cache)
    .map((d) => /^chromium-(\d+)$/.exec(d))
    .filter(Boolean)
    .sort((a, b) => Number(b[1]) - Number(a[1]));
  const candidates = [
    "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
    "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
    "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
    "chrome-linux64/chrome",
    "chrome-linux/chrome",
  ];
  for (const [dir] of revisions) {
    for (const c of candidates) {
      const path = join(cache, dir, c);
      if (existsSync(path)) return path;
    }
  }
  return null;
}

/** 没有找到浏览器时的提示。 */
export const NO_CHROMIUM = "没有找到 Playwright 的 Chromium（安装：npx playwright install chromium；或用 KEEVO_CHROME 指定）";

export async function launchChrome(chrome, args, env) {
  // 界面语言固定为中文：测试按中文文字断言（扩展按浏览器的界面语言选择中文或英文）。macOS 上 Chrome 不理会 --lang，
  // 界面语言取自应用的 AppleLanguages 偏好（CI 的运行器是英文系统）；在命令行上带 -AppleLanguages 又会让管道模式
  // 无法启动。因此对只用于测试的 Chrome for Testing 写入它自己的偏好，不改品牌版 Chrome 的设置。
  const lang = ["--lang=zh-CN"];
  if (process.platform === "darwin" && chrome.includes("Google Chrome for Testing.app")) {
    execFileSync("defaults", ["write", "com.google.chrome.for.testing", "AppleLanguages", "-array", "zh-CN"]);
  }
  const proc = spawn(chrome, [...args, ...lang, "--remote-debugging-pipe", "--enable-unsafe-extension-debugging"], {
    env,
    stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
  });
  let stderr = "";
  proc.stderr.on("data", (d) => {
    stderr += d;
    if (stderr.length > 20000) stderr = stderr.slice(-10000);
  });
  const writer = proc.stdio[3];
  const reader = proc.stdio[4];
  let buf = "";
  let next = 1;
  const waiting = new Map();
  const listeners = new Set();
  reader.on("data", (d) => {
    buf += d.toString("utf8");
    let i;
    while ((i = buf.indexOf("\0")) >= 0) {
      const msg = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      if (msg.id !== undefined && waiting.has(msg.id)) {
        const { resolve, reject } = waiting.get(msg.id);
        waiting.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message}（${JSON.stringify(msg.error.data ?? "")}）`));
        else resolve(msg.result);
      } else if (msg.method) {
        for (const l of listeners) l(msg);
      }
    }
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = next++;
      waiting.set(id, { resolve, reject });
      writer.write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`);
    });
  return {
    send,
    on(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    stderr: () => stderr,
    /**
     * 结束 Chrome 并等它退出（之后才能删除用户目录）。先经 DevTools 协议正常退出：品牌版 Chrome 退出时才会删除
     * 它在系统临时目录中的应用副本；5 秒内没有退出再强行结束。
     */
    async close() {
      if (proc.exitCode !== null || proc.signalCode !== null) return;
      const exited = new Promise((r) => proc.once("exit", r));
      send("Browser.close").catch(() => undefined);
      const timer = setTimeout(() => proc.kill("SIGKILL"), 5000);
      await exited;
      clearTimeout(timer);
    },
  };
}

/** 一个已附加的目标（页面或 iframe）。 */
export function session(browser, sessionId) {
  return {
    id: sessionId,
    send: (method, params) => browser.send(method, params, sessionId),
    async eval(expression) {
      const r = await browser.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
      if (r.exceptionDetails) throw new Error(`页面脚本出错：${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    },
  };
}

export async function attach(browser, targetId) {
  const { sessionId } = await browser.send("Target.attachToTarget", { targetId, flatten: true });
  return session(browser, sessionId);
}

export async function waitFor(fn, what, timeoutMs = 10000) {
  const until = Date.now() + timeoutMs;
  let last;
  while (Date.now() < until) {
    try {
      last = await fn();
      if (last) return last;
    } catch (e) {
      last = e;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`等待超时：${what}（最后的结果：${last instanceof Error ? last.message : JSON.stringify(last)}）`);
}

/** 在页面坐标处单击：DevTools 协议的输入事件是可信事件（isTrusted），与真实鼠标一样。 */
export async function click(page, x, y) {
  for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
    await page.send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
  }
}
