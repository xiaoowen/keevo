# iCloud 云盘普通文件夹验证

验证 Keevo 同步设计（`docs/sync.md` §4–§6）在 iCloud 云盘普通文件夹上是否可行。不需要任何证书、权限或 App ID。

```bash
swiftc -O spikes/icloud-folder/main.swift -o /tmp/keevo-icloud-spike
/tmp/keevo-icloud-spike /tmp/keevo-icloud-report.json
```

- 在 `~/Library/Mobile Documents/com~apple~CloudDocs/Keevo-iCloud-验证/<运行 ID>/` 下写入约 80 KB 的随机测试文件，结束后删除。删除的文件会在 iCloud 的「最近删除」中保留 30 天。
- 报告中的路径已把主目录替换为 `~`。
- 结论见 [docs/spikes/2026-11-18-icloud-folder.md](../../docs/spikes/2026-11-18-icloud-folder.md)。

验证 Dropbox、OneDrive 等同步文件夹时，把程序中的 `drive` 路径换成 `~/Library/CloudStorage/` 下对应的目录即可。
