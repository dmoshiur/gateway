/* Superadmin console */
(function () {
  "use strict";

  const api = {
    stats: "/api/v1/admin/stats",
    merchants: "/api/v1/admin/merchants",
    devices: "/api/v1/admin/devices",
    transactions: "/api/v1/admin/transactions",
    sms: "/api/v1/admin/sms",
  };

  const badge = (s) => `<span class="badge badge-${s}">${s}</span>`;
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function get(url) { return (await fetch(url)).json(); }

  function renderStats(s) {
    const cards = [
      { label: "Merchants", value: s.merchants, accent: true },
      { label: "Devices", value: s.devices },
      { label: "Transactions", value: s.transactions },
      { label: "Verified Volume", value: "৳ " + (s.volume || 0).toLocaleString() },
    ];
    document.getElementById("stats").innerHTML = cards.map((c) => `
      <div class="glass stat">
        <div class="label">${c.label}</div>
        <div class="value ${c.accent ? "accent" : ""}">${c.value}</div>
      </div>`).join("");
  }

  async function loadMerchants() {
    const d = await get(api.merchants);
    document.getElementById("pane-merchants").innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Email</th><th>Keys</th><th>Status</th><th>Created</th><th></th></tr></thead>
        <tbody>
        ${d.merchants.map((m) => `
          <tr>
            <td>${esc(m.name)}</td>
            <td class="mono">${esc(m.email)}</td>
            <td>${m.key_count}</td>
            <td>${m.is_active ? badge("active") : badge("inactive")}</td>
            <td class="muted small">${esc((m.created_at || "").slice(0, 10))}</td>
            <td><button class="btn btn-sm ${m.is_active ? "btn-danger" : ""}" onclick="toggleMerchant(${m.id})">
              ${m.is_active ? "Deactivate" : "Activate"}</button></td>
          </tr>`).join("")}
        </tbody></table></div>`;
  }

  async function loadDevices() {
    const d = await get(api.devices);
    document.getElementById("pane-devices").innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Device ID</th><th>Last Seen</th><th>Status</th><th></th></tr></thead>
        <tbody>
        ${d.devices.map((v) => `
          <tr>
            <td>${esc(v.name)}</td>
            <td class="mono">${esc(v.device_id)}</td>
            <td class="muted small">${esc(v.last_seen_at || "—")}</td>
            <td>${v.is_active ? badge("active") : badge("inactive")}</td>
            <td><button class="btn btn-sm ${v.is_active ? "btn-danger" : ""}" onclick="toggleDevice(${v.id})">
              ${v.is_active ? "Deactivate" : "Activate"}</button></td>
          </tr>`).join("")}
        </tbody></table></div>`;
  }

  async function loadTransactions() {
    const d = await get(api.transactions);
    document.getElementById("pane-transactions").innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>#</th><th>Merchant</th><th>TrxID</th><th>Amount</th><th>Provider</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
        ${d.transactions.map((t) => `
          <tr>
            <td>${t.id}</td>
            <td>${esc(t.merchant_name || "—")}</td>
            <td class="mono">${esc(t.trx_id)}</td>
            <td>৳ ${(t.amount || 0).toLocaleString()}</td>
            <td>${esc(t.provider || "—")}</td>
            <td>${badge(t.status)}</td>
            <td class="muted small">${esc((t.created_at || "").slice(0, 16).replace("T", " "))}</td>
          </tr>`).join("")}
        </tbody></table></div>`;
  }

  async function loadSms() {
    const d = await get(api.sms);
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
          </tr>`).join("")}
        </tbody></table></div>`;
  }

  window.toggleMerchant = async function (id) {
    await fetch(`/api/v1/admin/merchants/${id}/toggle`, { method: "POST" });
    loadMerchants();
  };
  window.toggleDevice = async function (id) {
    await fetch(`/api/v1/admin/devices/${id}/toggle`, { method: "POST" });
    loadDevices();
  };

  function bindTabs() {
    document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      document.querySelectorAll(".pane").forEach((p) => (p.style.display = "none"));
      document.getElementById("pane-" + t.dataset.pane).style.display = "";
    }));
  }

  (async function init() {
    bindTabs();
    renderStats(await get(api.stats));
    await Promise.all([loadMerchants(), loadDevices(), loadTransactions(), loadSms()]);
  })();
})();
