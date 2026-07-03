const input    = document.getElementById("url-input");
const btn      = document.getElementById("scan-btn");
const barWrap  = document.getElementById("scan-bar-wrap");
const scanLbl  = document.getElementById("scan-label");
const fill     = document.getElementById("scan-fill");
const card     = document.getElementById("result-card");
const icon     = document.getElementById("verdict-icon");
const vtext    = document.getElementById("verdict-text");
const scoreEl  = document.getElementById("score-value");
const urlEl    = document.getElementById("result-url");
const flagsEl  = document.getElementById("flags-list");
const flagsSec = document.getElementById("flags-section");
const noFlags  = document.getElementById("no-flags");
const whoisPanel = document.getElementById("whois-panel");
const whoisGrid  = document.getElementById("whois-grid");
const whoisErr   = document.getElementById("whois-error");

input.addEventListener("keydown", e => {
  if (e.key === "Enter") scan();
});

function prefill(url) {
  input.value = url;
  input.focus();
}

async function scan() {
  const url = input.value.trim();
  if (!url) return;

  // reset
  card.className = "result-card";
  card.classList.remove("visible");
  barWrap.classList.add("active");
  fill.style.width = "0%";
  btn.disabled = true;

  // two-phase animation: heuristics then WHOIS
  scanLbl.innerHTML = 'scanning heuristics<span class="dots"></span>';
  setTimeout(() => fill.style.width = "45%", 50);
  setTimeout(() => {
    scanLbl.innerHTML = 'querying WHOIS<span class="dots"></span>';
    fill.style.width = "75%";
  }, 700);

  try {
    const res  = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    fill.style.width = "100%";

    setTimeout(() => {
      barWrap.classList.remove("active");
      fill.style.width = "0%";
      renderResult(data);
    }, 400);

  } catch (err) {
    barWrap.classList.remove("active");
    btn.disabled = false;
    alert("Error contacting server.");
  }
}

async function loadHistory() {

    const response = await fetch("/history");

    const history = await response.json();

    const container = document.getElementById("history");

    container.innerHTML = "";

    history.forEach(scan => {

        container.innerHTML += `
            <div class="history-item">

                <span>${scan.url}</span>

                <span>${scan.verdict}</span>

                <span>Score ${scan.score}</span>

            </div>
        `;

    });

}

function renderResult(data) {
  const icons = { legitimate: "✅", suspicious: "⚠️", phishing: "🚨" };

  card.classList.add("visible", data.verdict);
  icon.textContent    = icons[data.verdict] ?? "?";
  vtext.textContent   = data.verdict;
  scoreEl.textContent = data.score;
  urlEl.textContent   = data.url;

  // WHOIS panel
  whoisGrid.innerHTML = "";
  whoisErr.textContent = "";
  whoisPanel.style.display = "none";
  whoisErr.style.display   = "none";

  const w = data.whois;
  if (w && !w.error) {
    whoisPanel.style.display = "block";
    const fields = [
      ["domain",      w.domain],
      ["age",         w.age_str],
      ["registered",  w.creation_date],
      ["expires",     w.expiration_date],
      ["registrar",   w.registrar],
    ];
    fields.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "whois-row";
      row.innerHTML = `<span class="whois-key">${label}</span><span class="whois-val">${value ?? "—"}</span>`;
      whoisGrid.appendChild(row);
    });
  } else if (w && w.error) {
    whoisErr.style.display = "block";
    whoisErr.textContent = `// WHOIS unavailable: ${w.error}`;
  }

  // flags
  flagsEl.innerHTML = "";
  if (data.flags && data.flags.length > 0) {
    flagsSec.style.display = "block";
    noFlags.style.display  = "none";
    data.flags.forEach(([name, pts]) => {
      const li = document.createElement("li");
      li.className = "flag-item";
      li.innerHTML = `<span class="flag-name">${name}</span><span class="flag-score">+${pts}</span>`;
      flagsEl.appendChild(li);
    });
  } else {
    flagsSec.style.display = "none";
    noFlags.style.display  = "block";
  }

  btn.disabled = false;
}