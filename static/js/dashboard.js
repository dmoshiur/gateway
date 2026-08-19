/* Merchant dashboard */
(function () {
  "use strict";

  const badge = (s) => `<span class="badge badge-${s}">${s}</span>`;
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function get(url) { return (await fetch(url)).json(); }
  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    return res.json();
  }

  function toast(msg, type) {
    let wrap = document.querySelector(".toast-wrap");
    if (!wrap) { wrap = document.createElement("div"); wrap.className = "toast-wrap"; document.body.appendChild(wrap); }
    const t = document.createElement("div");
    t.className = "toast " + (type || "");
    t.textContent = msg;
    wrap.appendChild(t);
    setTimeout(() => t.remove(), 3400);
  }

  async function loadStats() {
    const s = await get("/api/v1/dashboard/stats");
    const cards = [
      { label: "Total Transactions", value: s.total, accent: true },
      { label: "Verified", value: s.verified },
      { label: "Pending", value: s.pending },
      { label: "Verified Volume", value: "৳ " + (s.volume || 0).toLocaleString() },
    ];
    document.getElementById("stats").innerHTML = cards.map((c) => `
      <div class="glass stat">
        <div class="label">${c.label}</div>
        <div class="value ${c.accent ? "accent" : ""}">${c.value}</div>
      </div>`).join("");
  }

  async function loadKeys() {
    const d = await get("/api/v1/dashboard/keys");
    const box = document.getElementById("keys");
    if (!d.keys.length) {
      box.innerHTML = `<p class="muted small">No API keys yet. Generate one to start accepting payments.</p>`;
      return;
    }
    box.innerHTML = d.keys.map((k) => `
      <div class="glass-strong" style="padding:14px; margin-bottom:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
          <div>
            <strong>${esc(k.label)}</strong>
            <div class="muted small mono" style="word-break:break-all;">${esc(k.api_key)}</div>
          </div>
          ${k.is_active ? badge("active") : badge("inactive")}
        </div>
        <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
          <button class="btn btn-sm" onclick="copyText('${esc(k.api_key)}')">Copy Key</button>
          ${k.is_active ? `<button class="btn btn-sm btn-danger" onclick="revokeKey(${k.id})">Revoke</button>` : ""}
        </div>
      </div>`).join("");
  }

  async function loadTransactions() {
    const d = await get("/api/v1/dashboard/transactions");
    document.getElementById("pane-transactions").innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>#</th><th>TrxID</th><th>Amount</th><th>Provider</th><th>Phone</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
        ${d.transactions.map((t) => `
          <tr>
            <td>${t.id}</td>
            <td class="mono">${esc(t.trx_id)}</td>
            <td>৳ ${(t.amount || 0).toLocaleString()}</td>
            <td>${esc(t.provider || "—")}</td>
            <td class="mono">${esc(t.customer_phone || "—")}</td>
            <td>${badge(t.status)}</td>
            <td class="muted small">${esc((t.created_at || "").slice(0, 16).replace("T", " "))}</td>
          </tr>`).join("") || `<tr><td colspan="7" class="muted">No transactions yet.</td></tr>`}
        </tbody></table></div>`;
  }

  async function loadSms() {
    const d = await get("/api/v1/dashboard/sms");
    document.getElementById("pane-sms").innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>Provider</th><th>Sender</th><th>Amount</th><th>TrxID</th><th>Status</th><th>Received</th></tr></thead>
        <tbody>
        ${d.sms.map((s) => `
          <tr>
            <td>${esc(s.provider)}</td>
            <td class="mono">${esc(s.sender_number || "—")}</td>
            <td>৳ ${(s.amount || 0).toLocaleString()}</td>
            <td class="mono">${esc(s.trx_id)}</td>
            <td>${badge(s.status)}</td>
            <td class="muted small">${esc((s.created_at || "").slice(0, 16).replace("T", " "))}</td>
          </tr>`).join("") || `<tr><td colspan="6" class="muted">No SMS received yet.</td></tr>`}
        </tbody></table></div>`;
  }

  window.copyText = async function (text) {
    try { await navigator.clipboard.writeText(text); toast("Copied to clipboard", "success"); }
    catch { toast("Copy failed", "error"); }
  };
  window.revokeKey = async function (id) {
    await post(`/api/v1/dashboard/keys/${id}/revoke`);
    loadKeys();
  };

  function bindTabs() {
    document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      document.querySelectorAll(".pane").forEach((p) => (p.style.display = "none"));
      document.getElementById("pane-" + t.dataset.pane).style.display = "";
    }));
  }

  document.getElementById("gen-key").addEventListener("click", async () => {
    const label = prompt("Label for this API key:", "Production key");
    if (label == null) return;
    const r = await post("/api/v1/merchant/keys/generate", { label });
    if (r.ok) {
      toast(`Key created: ${r.api_key}`, "success");
      loadKeys();
    }
  });

  document.getElementById("sim-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await post("/api/v1/sandbox/simulate", {
      provider: document.getElementById("sim-provider").value,
      amount: document.getElementById("sim-amount").value,
      phone: document.getElementById("sim-phone").value,
    });
    if (r.ok) {
      document.getElementById("sim-result").innerHTML = `
        <div class="alert alert-success">
          <div><strong>SMS simulated</strong><br>
          <span class="small">TrxID <span class="mono">${esc(r.trx_id)}</span> · ৳ ${r.amount} · ${esc(r.provider)}</span></div>
        </div>`;
      loadSms();
      loadTransactions();
      loadStats();
    } else {
      document.getElementById("sim-result").innerHTML = `<div class="alert alert-error">${esc(r.error || "Failed")}</div>`;
    }
  });

  (async function init() {
    bindTabs();
    await Promise.all([loadStats(), loadKeys(), loadTransactions(), loadSms()]);
  })();
})();
