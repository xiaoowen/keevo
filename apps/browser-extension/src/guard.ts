// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 页内界面（页内菜单、保存栏）共用的点击劫持防护（docs/security.md §12）：
// - 用 IntersectionObserver v2（trackVisibility）判断界面是否真的可见：被遮挡、透明、加滤镜或变形都算不可见；
// - 连续可见满 500 毫秒后才接受点击，防止页面在用户点击的瞬间把界面移到光标下；
// - 只接受可信事件；持续不可见超过 1 秒时被点击，交给 onBlocked 处理（关闭界面，改用工具栏中的弹窗）。
//   界面改变大小或位置时可能短暂判定为不可见，这时的点击同样不生效，但不触发 onBlocked。
// 可用时给 <body> 加上 armed 类，样式据此显示按钮是否可用。

const MIN_VISIBLE_MS = 500;
const BLOCKED_AFTER_MS = 1000;

export interface Guard {
  /** 已连续可见足够久，可以接受点击。 */
  ready(): boolean;
  /** 点击前的检查：通过才执行操作。 */
  check(e: Event): boolean;
}

export function createGuard(target: Element, onBlocked: () => void): Guard {
  let visibleSince: number | null = null;
  let hiddenSince = performance.now();
  const ready = (): boolean => visibleSince !== null && performance.now() - visibleSince >= MIN_VISIBLE_MS;
  const update = (): void => {
    document.body.classList.toggle("armed", ready());
  };
  const observer = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        const v = (e as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true;
        if (v && visibleSince === null) {
          visibleSince = performance.now();
          setTimeout(update, MIN_VISIBLE_MS + 10);
        } else if (!v && visibleSince !== null) {
          visibleSince = null;
          hiddenSince = performance.now();
        }
        update();
      }
    },
    // trackVisibility 与 delay 是 v2 的选项（lib.dom 尚未收录）
    { threshold: [1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
  );
  observer.observe(target);
  return {
    ready,
    check(e: Event): boolean {
      if (!e.isTrusted) return false;
      if (ready()) return true;
      if (visibleSince === null && performance.now() - hiddenSince >= BLOCKED_AFTER_MS) onBlocked();
      return false;
    },
  };
}
