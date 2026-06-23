const input    = document.getElementById("url-input");
const btn      = document.getElementById("scan-btn");
const barWrap  = document.getElementById("scan-bar-wrap");
const fill     = document.getElementById("scan-fill");
const card     = document.getElementById("result-card");
const icon     = document.getElementById("verdict-icon");
const vtext    = document.getElementById("verdict-text");
const scoreEl  = document.getElementById("score-value");
const urlEl    = document.getElementById("result-url");
const flagsEl  = document.getElementById("flags-list");
const flagsSec = document.getElementById("flags-section");
const noFlags  = document.getElementById("no-flags");

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

  // animate bar
  setTimeout(() => fill.style.width = "60%", 50);
  setTimeout(() => fill.style.width = "85%", 400);

  try {
    const res  = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    setTimeout(() => fill.style.width = "100%", 200);

    setTimeout(() => {
      barWrap.classList.remove("active");
      fill.style.width = "0%";
      renderResult(data);
    }, 600);

  } catch (err) {
    barWrap.classList.remove("active");
    btn.disabled = false;
    alert("Error contacting server.");
  }
}

function renderResult(data) {
  const icons = { legitimate: "✅", suspicious: "⚠️", phishing: "🚨" };

  card.classList.add("visible", data.verdict);
  icon.textContent   = icons[data.verdict] ?? "?";
  vtext.textContent  = data.verdict;
  scoreEl.textContent = data.score;
  urlEl.textContent  = data.url;

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