# 离线指令授权快照复核台

地面审查员在无网络环境下，导入一份**指令授权快照**：32 字节根哈希、
十六进制指令标识，以及一组**按根到叶排序的 RLP 节点**（Merkle Patricia
Trie 证明）。系统逐层核验父子引用并回放半字节路径：

- 证明有效、路径完整抵达叶节点且**叶值恰为 `01`** → 结果页显示
  **“已授权”**；
- 路径可完整抵达叶节点但叶值非 `01` → 显示 **“未授权”**，并保留完整
  路径证据；
- 父子引用不符、重复尾节点、路径残缺、十六进制前缀错误、RLP 非规范或
  截断 → 标记**首个失败层**，清除旧成功结论，显示 **“证明无效”**。

每个结果页逐层列出：节点类型、引用方式（根承诺 / 32 字节散列 / 内嵌
节点）、节点摘要（Keccak-256）、本层消费半字节、累计已消费路径、
下一跳引用方式与原始 RLP，供审查员逐层回放。

## 组成

| 路径 | 说明 |
| --- | --- |
| `app/keccak.py` | 无第三方依赖的 Keccak-256（以太坊 0x01 填充变体） |
| `app/rlp.py` | 严格规范 RLP 编解码（拒绝非规范长度/截断/多余字节） |
| `app/hp.py` | 十六进制紧凑路径（hex-prefix）编解码 |
| `app/trie.py` | MPT 证明核验器（逐层追踪）+ 内存 trie 构建器 |
| `app/server.py` | 标准库 HTTP 服务（静态入口 + JSON API + 健康检查） |
| `scripts/build_snapshot.py` | 生成确定性离线快照 `data/snapshot.json` |
| `scripts/acceptance.py` | 验收运行器（三场景穿插，退出码报告） |
| `webstatic/` | 复核页面（`index.html` / `styles.css` / `app.js`） |
| `tests/` | 60 项单元/页面/HTTP 测试 |

Keccak-256 与 trie 根/证明均已用标准向量和权威 `pycryptodome`、`py-trie`
做过随机交叉验证。

## 本地运行（无需 Docker）

```bash
python scripts/build_snapshot.py        # 生成 data/snapshot.json
PORT=8080 python -m app.server          # 启动页面与 API
# 浏览器打开 http://localhost:8080
curl http://localhost:8080/healthz      # {"status": "ok"}
```

手动导入时，在页面表单中粘贴根哈希、指令标识（每行一个节点）或直接
调用接口：

```bash
curl -X POST http://localhost:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"root_hash":"0x…","command_id":"0x…","proof":["0x…","0x…"]}'
```

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## Docker Compose 验收

宿主端口可通过 `HOST_PORT` 配置（默认 8080）：

```bash
HOST_PORT=9090 docker compose up -d web        # 页面 http://localhost:9090
docker compose run --rm verify                 # 一次性验收，按退出码报告
# 或： docker compose up --build verify         # 构建并运行后退出
```

`verify` 服务会等待 `web` 健康检查通过，然后在**有效授权、篡改子节点
引用、非规范 RLP** 三个场景间穿插执行：

1. 证明核验相关代码测试（`unittest`）；
2. 页面构建检查（静态资源、元素 id、CSS 类、JS 语法）；
3. 对运行中服务的页面与健康端点的 API/HTTP 冒烟。

全部通过退出码为 `0`，任一失败退出码为 `1`。

## 快照场景

`data/snapshot.json` 内置 11 个夹具：8 个有效指令（启用/未授权）、
篡改子节点引用、非规范 RLP（`0x8101`）与路径残缺（缺失尾节点），
页面“快照夹具回放”表格中可逐一回放。
