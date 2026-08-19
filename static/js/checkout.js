/* ==========================================================================
   Checkout UI — Bangladesh-style MFS selection portal
   ========================================================================== */
(function () {
  "use strict";

  const root = document.getElementById("checkout-root");
  const token = root.dataset.token;
  const merchantName = root.dataset.merchant || "Merchant";
  // Demo amount: overridable via ?amount=1234.56 (real flows inject this server-side).
  const params = new URLSearchParams(location.search);
  const amount = (parseFloat(params.get("amount")) || 500.0).toFixed(2);

  const PROVIDERS = {
    mfs: [
      { key: "bkash",     name: "bKash",    cls: "bkash",     mark: "bK" },
      { key: "nagad",     name: "Nagad",    cls: "nagad",     mark: "N"  },
      { key: "rocket",    name: "Rocket",   cls: "rocket",    mark: "R"  },
      { key: "upay",      name: "Upay",     cls: "upay",      mark: "U"  },
      { key: "tap",       name: "Tap",      cls: "tap",       mark: "T"  },
      { key: "meghnapay", name: "Meghna Pay", cls: "meghnapay", mark: "M" },
    ],
    cards: [
      { key: "visa",       name: "Visa",       cls: "card", mark: "V" },
      { key: "mastercard", name: "Mastercard", cls: "card", mark: "MC" },
      { key: "amex",       name: "Amex",       cls: "card", mark: "AX" },
    ],
    bank: [
      { key: "ebl",  name: "EBL",  cls: "bank", mark: "EBL" },
      { key: "dbbl", name: "DBBL", cls: "bank", mark: "DB" },
      { key: "city", name: "City", cls: "bank", mark: "CB" },
    ],
  };

  const TAB_LABELS = { mfs: "MFS / Wallet", cards: "Cards", bank: "Internet Banking" };

  let activeTab = "mfs";
  let selectedProvider = null;
  let step = 1;

  /* ---- render -------------------------------------------------------- */
  function render() {
    root.innerHTML = `
      <div class="section" style="margin-top: 30px;">
        <div class="glass-strong pad" style="max-width: 620px; margin: 0 auto;">
          <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
            <div>
              <p class="muted small" style="margin:0;">Paying to</p>
              <h2 style="margin:2px 0 0;">${escapeHtml(merchantName)}</h2>
            </div>
            <div style="text-align:right;">
              <p class="muted small" style="margin:0;">Amount</p>
              <div class="gradient-text" style="font-size:1.9rem; font-weight:800;">৳ ${amount}</div>
            </div>
          </div>

          <div class="tabs" style="margin-top:20px;">
            ${Object.keys(TAB_LABELS).map((t) => `
              <button class="tab ${t === activeTab ? "active" : ""}" data-tab="${t}">
                ${TAB_LABELS[t]}
              </button>`).join("")}
          </div>

          <div class="provider-grid" style="margin-top:16px;">
            ${PROVIDERS[activeTab].map((p) => `
              <div class="provider" data-provider="${p.key}">
                <div class="logo-tile ${p.cls}">${p.mark}</div>
                <div class="name">${p.name}</div>
                <div class="hint">${activeTab === "mfs" ? "Wallet" : activeTab === "cards" ? "Card" : "Bank"}</div>
              </div>`).join("")}
          </div>

          ${activeTab === "mfs"
            ? `<p class="muted small" style="margin-top:16px;">
                 Select your wallet above, send the exact amount from your number, then enter the TrxID
                 from the confirmation SMS.</p>`
            : `<div class="alert alert-warn" style="margin-top:16px;">
                 ${activeTab === "cards" ? "Card payments" : "Internet banking"} are not enabled in this demo.
                 Please use an MFS wallet.</div>`}
        </div>
      </div>

      ${modal()}
    `;

    root.querySelectorAll(".tab").forEach((el) =>
      el.addEventListener("click", () => { activeTab = el.dataset.tab; selectedProvider = null; step = 1; render(); }));

    root.querySelectorAll(".provider").forEach((el) =>
      el.addEventListener("click", () => {
        selectedProvider = el.dataset.provider;
        if (activeTab !== "mfs") { toast("This payment method is coming soon", "error"); return; }
        step = 1;
        openModal();
      }));

    document.getElementById("modal-backdrop").addEventListener("click", (e) => {
      if (e.target.id === "modal-backdrop") closeModal();
    });
    document.getElementById("modal-close").addEventListener("click", closeModal);
    document.getElementById("verify-form").addEventListener("submit", onSubmit);
    document.getElementById("btn-next").addEventListener("click", onNext);
  }

  /* ---- modal --------------------------------------------------------- */
  function modal() {
    const p = PROVIDERS.mfs.find((x) => x.key === selectedProvider) || { name: "", cls: "" };
    return `
    <div class="modal-backdrop" id="modal-backdrop">
      <div class="modal glass-strong pad">
        <div class="modal-head">
          <h3 style="margin:0; display:flex; align-items:center; gap:10px;">
            <span class="logo-tile ${p.cls}" style="width:34px;height:34px;border-radius:9px;font-size:.8rem;">${p.name.slice(0,2)}</span>
            Pay with ${p.name || "Wallet"}
          </h3>
          <button class="modal-close" id="modal-close">&times;</button>
        </div>

        <div class="steps">
          <div class="step active" id="step-1"></div>
          <div class="step" id="step-2"></div>
          <div class="step" id="step-3"></div>
        </div>

        <form id="verify-form">
          <div class="field" id="field-phone">
            <label>Your Wallet Number</label>
            <input id="phone" inputmode="numeric" placeholder="01XXXXXXXXX" required>
          </div>
          <div class="field" id="field-trx" style="display:none;">
            <label>Transaction ID (TrxID) from the SMS</label>
            <input id="trx_id" placeholder="e.g. 8JX4A2B3C4" required>
          </div>

          <div id="verify-box" style="display:none; text-align:center; padding:16px 0;">
            <div class="spinner spinner-lg" style="margin:0 auto 14px;"></div>
            <p class="muted" id="verify-text">Verifying your payment…</p>
          </div>

          <div id="result-box" style="display:none;"></div>

          <div id="actions">
            <button type="button" class="btn btn-block" id="btn-next" style="margin-top:6px;">Continue</button>
            <button type="submit" class="btn btn-primary btn-block" id="btn-verify" style="display:none; margin-top:6px;">Verify Payment</button>
            <button type="button" class="btn btn-ghost btn-block" id="btn-again" style="display:none; margin-top:6px;">Try again</button>
          </div>
        </form>
      </div>
    </div>`;
  }

  /* ---- modal controls ------------------------------------------------- */
  function openModal() { render(); document.getElementById("modal-backdrop").classList.add("open"); }
  function closeModal() { document.getElementById("modal-backdrop").classList.remove("open"); }
  function setStep(n) {
    step = n;
    for (let i = 1; i <= 3; i++) {
      const el = document.getElementById(`step-${i}`);
      el.classList.toggle("active", i === n);
      el.classList.toggle("done", i < n);
    }
  }

  /* ---- flow ----------------------------------------------------------- */
  function onNext() {
    if (step === 1) {
      const phone = document.getElementById("phone").value.trim();
      if (!/^01[3-9]\d{8}$/.test(phone.replace(/[^0-9]/g, ""))) {
        toast("Enter a valid 11-digit mobile number (01XXXXXXXXX)", "error");
        return;
      }
      document.getElementById("field-phone").style.display = "none";
      document.getElementById("field-trx").style.display = "";
      document.getElementById("btn-next").style.display = "none";
      document.getElementById("btn-verify").style.display = "";
      setStep(2);
    }
  }

  function onSubmit(e) {
    e.preventDefault();
    const trx = document.getElementById("trx_id").value.trim();
    if (!trx) { toast("Please enter the TrxID", "error"); return; }

    // Step 3: verifying
    document.getElementById("field-trx").style.display = "none";
    document.getElementById("btn-verify").style.display = "none";
    document.getElementById("verify-box").style.display = "";
    setStep(3);

    verifyPayment(trx);
  }

  async function verifyPayment(trxId) {
    const phone = document.getElementById("phone").value.trim().replace(/[^0-9]/g, "");
    const body = {
      checkout_token: token,
      trx_id: trxId,
      amount: parseFloat(amount),
      provider: selectedProvider,
      customer_phone: phone,
    };

    try {
      const res = await fetch("/api/v1/checkout/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      renderResult(data, res.ok);
    } catch (err) {
      renderResult({ status: "error", message: "Network error — check your connection." }, false);
    }
  }

  function renderResult(data, ok) {
    document.getElementById("verify-box").style.display = "none";
    const box = document.getElementById("result-box");
    box.style.display = "";
    document.getElementById("btn-again").style.display = "";

    const status = data.status || "error";
    if (status === "verified") {
      box.innerHTML = `
        <div class="alert alert-success">
          <div style="font-size:1.4rem;">✔</div>
          <div><strong>Payment verified!</strong><br><span class="small muted">${escapeHtml(data.message || "Thank you.")}</span></div>
        </div>`;
      setStep(3);
    } else if (status === "pending") {
      box.innerHTML = `
        <div class="alert alert-warn">
          <div style="font-size:1.4rem;">⏳</div>
          <div><strong>Not received yet</strong><br><span class="small muted">${escapeHtml(data.message || "Waiting for the SMS.")}</span></div>
        </div>`;
    } else {
      box.innerHTML = `
        <div class="alert alert-error">
          <div style="font-size:1.4rem;">✖</div>
          <div><strong>${status === "mismatch" ? "Details don't match" : "Verification failed"}</strong><br>
          <span class="small muted">${escapeHtml(data.message || data.error || "Please check the TrxID and try again.")}</span></div>
        </div>`;
    }
    document.getElementById("btn-again").onclick = () => {
      step = 1; selectedProvider = null; closeModal(); render();
    };
  }

  /* ---- toast ---------------------------------------------------------- */
  function toast(msg, type) {
    let wrap = document.querySelector(".toast-wrap");
    if (!wrap) { wrap = document.createElement("div"); wrap.className = "toast-wrap"; document.body.appendChild(wrap); }
    const t = document.createElement("div");
    t.className = "toast " + (type || "");
    t.textContent = msg;
    wrap.appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  render();
})();
