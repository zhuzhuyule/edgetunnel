# tunnel-only · 出口配置契约（v1）

> 本文件定义前后端与 Worker 之间的唯一数据契约。**先冻结本契约，再落地 Worker 与前端对接**，避免来回改。
> 存储载体：CF KV，键名 `egress.json`（可选覆盖键由 `env.EGRESS_KEY` 指定）。

---

## 1. 存储模型 `egress.json`

Worker 启动（或首次命中）读取一次，缓存于 isolate 内；写入口由管理台触发刷新。

```jsonc
{
  "version": 1,                 // 契约版本，预留向后兼容
  "default": "jp-tokyo",        // 默认出口档案名；命中不到 egress= 时用它
  "egress": [                   // 出口档案列表（顺序即优先级/展示顺序）
    {
      "name": "jp-tokyo",       // 唯一键，用于 ?egress= 与订阅节点备注
      "type": "socks5",         // "socks5" | "proxy"（proxy=反代 host:port）
      "value": "user:pass@1.2.3.4:1080",  // socks5: user:pass@host:port；proxy: host:port
      "remark": "东京 · 低延迟",  // 可选备注
      "enabled": true           // 可选，false 则不出现在订阅与可选列表
    },
    {
      "name": "kr-seoul",
      "type": "proxy",
      "value": "cdn.example.com:443"
    }
  ],
  "prefs": [                    // 优选入口（客户端边缘优化，正交维度）
    { "ip": "104.16.0.1", "port": 443 },
    { "ip": "2606:4700::1111", "port": 443 }
  ]
}
```

### 字段规则
- `name`：`[A-Za-z0-9._-]`，唯一，用于 `?egress=name`；含特殊字符时订阅里做 `encodeURIComponent`。
- `type=socks5` → `value` 必须是 `user:pass@host:port` 或 `host:port`（无鉴权）。
- `type=proxy` → `value` 是 `host:port`，作为 VLESS 节点地址（反代/CDN）。
- `default` 必须指向某个 `enabled` 档案的 `name`；缺失时取第一个 `enabled` 档案。
- 订阅节点数公式：**enabled 出口数 × prefs 数**（无 prefs 时按出口数，host 用 proxy 值或占位域名）。

---

## 2. 前端导入/导出 JSON 契约

`egress-admin-preview.html` 的“导出/导入 JSON”**直接采用本结构**，保证“前端导出 → 贴到管理台/KV”零转换。

- 导出：`{ version:1, default, egress:[...], prefs:[...] }`，字段与 §1 一致。
- 导入：容错解析——
  - 接受旧版扁平数组（自动补 `version/default`）。
  - `egress[]` 项允许 `ip/port/ok/latency` 等前端字段，导入时丢弃运行时字段（`ok/latency`）。
  - `prefs[]` 允许字符串 `"1.2.3.4:443"`，自动规范为 `{ip,port}`。

---

## 3. Worker `?egress=` 语义

在 `反代参数获取` 之前拦截（tunnel-only 闸门内）：

1. 解析 `?egress=<name>`（可逗号分隔多值 `a,b`，取第一个命中的 enabled 档案）。
2. 命中 → **强制出口**：跳过直连 / PROXYIP 竞速拨号，直接按档案 `type` 走 SOCKS5 / 反代 拨号。
3. 未传 / 未命中 → 回退 `default` 档案；若整体无 enabled 档案 → 回退原始直连/PROXYIP 链（保证可用）。
4. 出口名写入响应，便于排障：`X-Egress: <name>`。

> 与 VLESS 内层目标地址无关；`egress` 决定的是 **Worker 出站到公网的最后一跳**，优选 `prefs` 决定的是**客户端连哪个 CF 边缘**，二者正交。

---

## 4. 动态订阅 `/sub?egress=<name|a,b>`

替代旧 subconverter 本地生成，Worker 实时拼节点：

- `?egress=a`：只生成档案 `a` 的节点（出口数 1）。
- `?egress=a,b`：生成 a、b 两个档案的节点。
- 省略 `?egress=`：用 `default`。
- 节点模板：
  - `proxy` 出口 → `vless://<uuid>@<proxy-host>:<port>?path=/egress=<name>#<name>`
  - `socks5` 出口 → 客户端连 `prefs` 边缘：`vless://<uuid>@<pref.ip>:<pref.port>?path=/egress=<name>#<name>·<pref.ip>`
  - `full=true` 时 socks5 出口展开为「每个 pref × 该出口」。
- 鉴权：沿用现有 `?token=`（`MD5(host+userID)`）或新增 `env.SUB_KEY`，二选一，避免裸奔。
- 响应头：`Profile-Update-Interval`、`Profile-web-page-url`（指向新管理台地址）、`Content-Disposition`（非浏览器 UA 时附件）。

---

## 5. 前后端对齐清单（落地前逐项打勾）

- [ ] 前端“导出 JSON”字段 == §2（含 `default` 出口选择器）。
- [ ] 管理台写入 KV 的键名 == `egress.json`（或 `env.EGRESS_KEY`）。
- [ ] Worker `?egress=` 解析命中/回退逻辑 == §3。
- [ ] `/sub` 动态节点公式 == §4。
- [ ] 前端“检测”改为调用真实探针端点（替换当前哈希模拟），返回 `{ok,latency}`。
- [ ] `discoverVpngate` 验证 VPS `:8787/api/status` CORS 后接入真实端口。

---

## 6. 待你拍板的开放项

1. **订阅鉴权**：沿用 `?token=` 还是新增 `env.SUB_KEY`？（建议后者，独立于 admin 密码）
2. **KV 键名**：固定 `egress.json`，还是允许 `env.EGRESS_KEY` 覆盖？
3. **prefs 是否随订阅动态**：prefs 固定存 KV，还是每请求拉优选 API？（建议固定 KV，简单可控）
4. **前端 `default`**：是否需要“按出口分组独立维护 prefs 子集”，还是全局一套 prefs？
