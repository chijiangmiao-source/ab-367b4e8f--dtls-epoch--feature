# 深空中继 · DTLS 1.3 遥测审计台

审查员用于复核深空中继转发的加密遥测捕获：确认重复捕获、过期序号或伪造的
KeyUpdate 不会被当作新的有效指令。

## 范围

- 仅接受 **无 CID 的 DTLS 1.3 统一头**（`001C SLEE`，C=0）
- 仅 **TLS_AES_128_GCM_SHA256**（SHA-256 HKDF / AES-128-GCM / 16 字节标签）
- 仅 **单方向** 记录；初始接收 epoch 与 32 字节 traffic secret 由页面提供
- 序号由原始头部截断字段恢复（RFC 9147 §4.2.2 / RFC 9000 §A.3）
- 记录密钥与 IV 按 TLS 1.3 标签派生（`HKDF-Expand-Label(secret, "key"/"iv", "")`）
- **AEAD 认证成功后才解开内部内容类型**（DTLSInnerPlaintext 去零填充）
- 每个 epoch 以 **最高序号 + 64 位位图** 裁定 新到 / 重复 / 过旧
- **合法 KeyUpdate 先经认证**，再派生下一 epoch 密钥（`"traffic upd"`）并重置窗口；
  失败、重复或旧 epoch 记录绝不推进秘密或当前窗口（旧 epoch 记录只更新其自身
  epoch 的重放状态，用于识别迟到的重放）
- 每个已建立 epoch 的接收密钥来源可沿**世代证据链**追查：初始 traffic secret
  （仅以不可逆指纹表示）或某条认证成功且实际推进的 KeyUpdate 记录序号；伪造、
  重复、过旧、旧 epoch 或未推进的记录一律排除在链外并列入失败边界

## 运行

```bash
docker compose up app                 # 默认宿主机端口 8080
HOST_PORT=9000 docker compose up app  # 可配置宿主机端口
```

打开 `http://localhost:8080/`：填写审计标识、初始 epoch、64 位十六进制
traffic secret，按捕获顺序粘贴至多 48 条 Base64 记录并提交；之后可用同一
审计标识重新打开冻结裁决。每条记录显示 epoch、完整序号、认证结果、重放窗口
前后状态与应用数据摘要（SHA-256）；存在违规时页面经 API 显示首个截断 / 长度 /
认证 / 状态违规的**原始偏移**（记录内字节偏移），同一审计标识再次提交会原子
替换旧裁决，旧成功证据随之清除。

## 验收（verify 容器）

```bash
docker compose up --exit-code-from verify
```

`verify` 容器随 Compose 启动（等待 app 健康检查通过），实际执行：

1. **构建检查** — 字节编译应用、导入服务模块、校验页面表单
2. **复核规则测试** — 重放窗口边界（偏移 63/64）、序号恢复、KeyUpdate
   推进纪律、伪造抵抗、RFC 5869 / AES-GCM 测试向量
3. **HTTP 冒烟** — 针对运行中的服务验证 KeyUpdate 推进与窗口重置、
   重放边界裁定、伪造 KeyUpdate 不推进秘密、截断/长度违规的原始偏移、
   再次提交后旧成功证据被清除，以及世代证据链（初始根、按序链边、指纹
   不可逆且衔接、失败边界、未知审计/未建立 epoch 的拒绝与跨审计隔离）

完成后容器退出，退出码即验收结果（0 = 通过，1 = 失败）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康响应 `{"status":"ok"}` |
| `GET` | `/` | 审计页面 |
| `POST` | `/api/audit` | 提交捕获并冻结裁决（替换同标识旧裁决） |
| `GET` | `/api/audit/{audit_id}` | 重新打开冻结裁决 |
| `GET` | `/api/audit/{audit_id}/epoch/{epoch}` | 某已建立 epoch 的接收密钥世代证据 |

`POST /api/audit` 请求体：

```json
{
  "audit_id": "relay-001",
  "initial_epoch": 3,
  "traffic_secret": "64 hex chars",
  "records": ["<base64 record>", "..."]
}
```

响应即冻结裁决：`ok`、`first_violation{record_index,kind,offset,message}`、
逐记录裁定（epoch/seq/replay/auth/窗口前后/摘要/违规，认证成功且实际推进的
KeyUpdate 记录另带 `lineage_edge` 边号）与最终接收状态
（当前 epoch、推进次数、各 epoch 窗口）。

冻结裁决还包含密钥**世代链** `lineage` 与失败边界 `chain_boundary`：

- `lineage.root` — 初始 epoch 与初始 traffic secret 的**不可逆指纹**
  （HMAC-SHA256，域分离常量做密钥）；原始 traffic secret 从不出现在任何响应中。
- `lineage.edges[]` — 按推进顺序排列的链边：只有**认证成功且实际推进接收
  状态**的 KeyUpdate 才是边；每条边给出记录序号（捕获内 `record_index`、该
  epoch 内完整序号 `seq`）、前后 epoch、前后 secret 指纹。
- `chain_boundary[]` — 携带类 KeyUpdate 含义却不得入链的记录及排除原因：
  `authentication_failed`（标签失败、内容未解开）、`old_epoch_not_advanced`
  （认证成功但属旧 epoch）、`authenticated_not_advanced`（认证成功但状态违规，
  如 KeyUpdate 畸形）、`replayed_key_update`（链上记录的重复/过旧投递，解密前
  丢弃）。认证失败、重复、过旧、旧 epoch 或未推进的记录绝不成为链边。

### 世代证据端点

`GET /api/audit/{audit_id}/epoch/{epoch}` 返回该 epoch 接收密钥的来源视图：

```json
{
  "audit_id": "...",
  "epoch": 4,
  "evidence": {
    "epoch": 4,
    "origin": "authenticated_key_update",
    "path_length_edges": 1,
    "nodes": [/* 初始根 → 各后继 epoch，含指纹 */],
    "edges": [/* 到该 epoch 为止的链边，linked 表示前后指纹衔接 */],
    "establishing_edge": 0,
    "establishing_record_index": 1,
    "establishing_record_seq": 1
  },
  "established_epochs": [3, 4],
  "chain_boundary": [/* 整个冻结审计的失败边界 */]
}
```

- `origin = initial_traffic_secret`（仅初始 epoch）或
  `authenticated_key_update`，并指明建立该 epoch 的具体记录与序号。
- 查询**不存在的审计**：`404`，与重新打开接口一致的不透明拒绝，不泄露其他
  审计的任何证据。
- 查询**存在但未建立的 epoch**：`404 epoch_not_established`，仅回显本审计已建立
  的 epoch 列表；**越界 epoch**（`..-1` / `65536..`）返回 `400`。
- 同一标识重新提交后旧链被原子替换，旧边的世代证据随即不可得。

页面在裁决表下方提供「世代证据」面板：下拉选择已建立的 epoch（默认追查最终
epoch），按推进顺序展示初始根、每次建立后继 epoch 的记录序号、前后 epoch 及
secret 指纹衔接，并单列失败边界；拒绝时显示明确原因且不跨审计泄露。

## 违规类型与偏移约定

| kind | 含义 | offset 指向 |
| --- | --- | --- |
| `truncation` | 记录被截断（头部字段不全、声明长度超出实际） | 解析中断/数据耗尽处 |
| `length` | 长度不一致（声明长度偏短、密文不足 16 字节标签、内部明文无类型字节） | 长度字段或密文起始 |
| `authentication` | AEAD 标签校验失败 | 标签起始（记录末尾 −16） |
| `state` | 状态违规（非统一头、含 CID、epoch 无密钥、KeyUpdate 畸形等） | 相关字段 |

## 本地开发（不用 Docker）

```bash
pip install -r requirements.txt
python -m unittest discover -s tests          # 复核规则测试
uvicorn server.main:app --port 8000           # 启动服务
APP_BASE_URL=http://127.0.0.1:8000 python verify.py   # 完整验收
```
