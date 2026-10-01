"use strict";

/* 离线指令授权快照复核台前端逻辑（无第三方依赖）。 */

const STATUS_LABEL = {
  AUTHORIZED: "已授权",
  UNAUTHORIZED: "未授权",
  INVALID: "证明无效"
};

const REF_LABEL = {
  root: "根承诺",
  hash: "32字节散列引用",
  embedded: "内嵌节点引用"
};

const NODE_LABEL = {
  branch: "分支节点",
  extension: "扩展节点",
  leaf: "叶节点"
};

function shortHex(value, head = 10, tail = 8) {
  if (!value) return "—";
  if (value.length <= head + tail + 2) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

async function postVerify(fixture) {
  const resp = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(fixture)
  });
  if (!resp.ok) {
    const detail = await resp.json().catch(() => ({}));
    throw new Error(detail.error || `HTTP ${resp.status}`);
  }
  return resp.json();
}

function keyLabel(keyHex) {
  const bytes = keyHex.startsWith("0x") ? keyHex.slice(2) : keyHex;
  if (bytes.length % 2 !== 0) return keyHex;
  let text = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const code = parseInt(bytes.slice(i, i + 2), 16);
    if (Number.isNaN(code) || code < 0x20 || code > 0x7e) return keyHex;
    text += String.fromCharCode(code);
  }
  return text ? `${keyHex}（ASCII: ${text}）` : keyHex;
}

function renderResult(result) {
  const panel = document.getElementById("result-panel");
  const verdict = document.getElementById("verdict");
  const meta = document.getElementById("meta");
  const failureBox = document.getElementById("failure-box");
  const layerBody = document.getElementById("layer-body");
  const leafLine = document.getElementById("leaf-line");

  panel.hidden = false;
  verdict.className = `verdict ${result.status}`;
  verdict.textContent = result.status_text;

  meta.innerHTML = `
    <div><b>根哈希：</b><span class="mono">${escapeHtml(result.root)}</span></div>
    <div><b>指令标识：</b><span class="mono">${escapeHtml(keyLabel(result.key))}</span></div>
    <div><b>判定依据：</b>证明有效且路径完整抵达叶节点时，叶值 <code>0x01</code>
      为已授权；叶值非 <code>01</code> 为未授权并保留路径证据；
      编码或引用异常则标明首个失败层并清除成功结论。</div>
  `;

  if (result.status === "INVALID") {
    failureBox.hidden = false;
    failureBox.innerHTML = `
      <b>首个失败层：第 ${result.failure_layer} 层</b><br/>
      已清除此前可能的成功结论。原因：${escapeHtml(result.failure_reason)}
    `;
  } else {
    failureBox.hidden = true;
  }

  const rows = (result.layers || []).map((layer) => `
    <tr>
      <td>${layer.layer}</td>
      <td class="node-kind-${layer.node_kind}">
        ${NODE_LABEL[layer.node_kind] || escapeHtml(layer.node_kind)}
      </td>
      <td class="mono tiny2 ref-${layer.ref_kind}">
        ${REF_LABEL[layer.ref_kind] || escapeHtml(layer.ref_kind)}
      </td>
      <td class="mono tiny">${escapeHtml(layer.actual_hash)}</td>
      <td class="mono">${escapeHtml(layer.consumed_nibbles)}</td>
      <td class="mono">${escapeHtml(layer.cumulative_path)}</td>
      <td class="mono tiny">
        ${layer.next_ref_kind
          ? `<span class="ref-${layer.next_ref_kind}">${REF_LABEL[layer.next_ref_kind]}</span><br/>
             <span class="muted">${escapeHtml(shortHex(layer.next_ref))}</span>`
          : "—"}
      </td>
      <td class="mono tiny muted">
        ${escapeHtml(shortHex(layer.raw_rlp_hex, 6, 6))}
        ${layer.note ? `<br/><span>${escapeHtml(layer.note)}</span>` : ""}
      </td>
    </tr>`);
  layerBody.innerHTML = rows.join("");

  if (result.status !== "INVALID") {
    leafLine.hidden = false;
    leafLine.textContent = `路径完整抵达叶节点，叶值 = ${result.leaf_value}（${
      result.status === "AUTHORIZED"
        ? "恰好为 01，指令被承诺为启用"
        : "不是 01，指令未被承诺为启用"}）——${result.status_text}。`;
  } else {
    leafLine.hidden = true;
  }
}

async function runFixture(fixture) {
  const failureBox = document.getElementById("failure-box");
  try {
    const result = await postVerify(fixture);
    renderResult(result);
  } catch (err) {
    document.getElementById("result-panel").hidden = false;
    const verdict = document.getElementById("verdict");
    verdict.className = "verdict INVALID";
    verdict.textContent = "请求失败";
    document.getElementById("layer-body").innerHTML = "";
    document.getElementById("leaf-line").hidden = true;
    failureBox.hidden = false;
    failureBox.innerHTML = `<b>服务端错误：</b>${escapeHtml(err.message)}`;
  }
}

async function loadFixtures() {
  const resp = await fetch("/api/snapshot");
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const snapshot = await resp.json();
  const expectLabel = {
    AUTHORIZED: "已授权", UNAUTHORIZED: "未授权", INVALID: "证明无效"
  };
  const body = document.getElementById("fixture-body");
  body.innerHTML = snapshot.fixtures.map((fx) => `
    <tr>
      <td>${escapeHtml(fx.name)}</td>
      <td class="mono tiny">${escapeHtml(fx.command_id)}</td>
      <td>${expectLabel[fx.expect] || escapeHtml(fx.expect)}</td>
      <td><button type="button" data-name="${escapeHtml(fx.name)}">回放</button></td>
    </tr>
  `).join("");
  body.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const fx = snapshot.fixtures.find((f) => f.name === btn.dataset.name);
      runFixture(fx);
    });
  });
}

function manualSubmit() {
  const root = document.getElementById("in-root").value.trim();
  const key = document.getElementById("in-key").value.trim();
  const proofText = document.getElementById("in-proof").value.trim();
  const proof = proofText
    ? proofText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
    : [];
  runFixture({ root_hash: root, command_id: key, proof });
}

document.getElementById("btn-verify").addEventListener("click", manualSubmit);
loadFixtures().catch((err) => {
  document.getElementById("fixture-body").innerHTML =
    `<tr><td colspan="4" class="muted">快照加载失败：${escapeHtml(err.message)}</td></tr>`;
});
