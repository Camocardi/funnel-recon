/**
 * content.js — roda isolado. Recebe os payloads, extrai anuncios,
 * detecta vazamentos, marca dominios outlier e desenha o painel.
 */

(() => {
  "use strict";

  // ===========================================================================
  // ESTADO
  // ===========================================================================
  const ads = new Map(); // ad_archive_id -> registro
  let autoScroll = false;
  let scrollTimer = null;
  let stagnantTicks = 0;
  let root = null; // shadow root do painel

  // ===========================================================================
  // EXTRACAO
  // ===========================================================================

  /** Percorre qualquer JSON sem depender do schema do Meta. */
  function walk(node, visit, depth = 0) {
    if (!node || typeof node !== "object" || depth > 30) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, visit, depth + 1);
      return;
    }
    visit(node);
    for (const key in node) walk(node[key], visit, depth + 1);
  }

  const ID_KEYS = ["ad_archive_id", "adArchiveID", "adArchiveId", "archive_id"];

  function findId(obj) {
    for (const k of ID_KEYS) {
      if (obj[k] != null && String(obj[k]).length > 6) return String(obj[k]);
    }
    return null;
  }

  /**
   * Desembrulha l.facebook.com/l.php?u=<destino>. O Meta envolve todo link de
   * saida nesse redirecionador; sem desembrulhar, todo anuncio parece apontar
   * para facebook.com e a analise de dominio nao serve pra nada.
   */
  function unwrapFacebookLink(raw) {
    if (!raw || typeof raw !== "string") return "";
    let url = raw.trim();
    for (let i = 0; i < 3; i++) {
      try {
        const parsed = new URL(url);
        const isRedirector =
          /(^|\.)facebook\.com$/i.test(parsed.hostname) &&
          /^\/l\.php$/i.test(parsed.pathname);
        if (!isRedirector) break;
        const target = parsed.searchParams.get("u");
        if (!target) break;
        url = decodeURIComponent(target);
      } catch (_) {
        break;
      }
    }
    return url;
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname.replace(/^www\./i, "").toLowerCase();
    } catch (_) {
      return "";
    }
  }

  /**
   * Dominios do proprio Meta. O fallback de DOM capturava links internos
   * (transparency.meta.com, fbcdn, instagram) e eles entravam no histograma
   * como se fossem destino de anuncio — foi ruido real na coleta de 236
   * anuncios. Filtrar so `facebook.com` nao bastava.
   */
  const META_HOST_RE =
    /(^|\.)(facebook\.com|fb\.com|fb\.me|fbcdn\.net|meta\.com|instagram\.com|whatsapp\.com|messenger\.com|threads\.net|oculus\.com)$/i;

  const isMetaHost = (host) => !host || META_HOST_RE.test(host);

  // --- deteccao de vazamento -------------------------------------------------
  // Cada padrao aponta para um canal de funil que escapou pro texto do anuncio.
  const LEAK_PATTERNS = [
    { tag: "telegram", re: /(?:t\.me|telegram\.me)\/(?:joinchat\/)?([A-Za-z0-9_+\-]{3,64})/gi },
    { tag: "telegram", re: /tg:\/\/resolve\?domain=([A-Za-z0-9_]{3,64})/gi },
    { tag: "bot-handle", re: /@([A-Za-z0-9_]{4,30}(?:bot|_bot))\b/gi },
    { tag: "whatsapp", re: /(?:wa\.me|api\.whatsapp\.com\/send\?phone=)\/?(\+?\d{8,15})/gi },
    { tag: "pixel", re: /fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,})['"]/gi },
    { tag: "tracker", re: /\b(kclickid|_subid|keitaro|binom|redtrack|clickid)\b/gi },
  ];

  function scanLeaks(text) {
    const out = new Set();
    for (const { tag, re } of LEAK_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        out.add(`${tag}:${m[1] || m[0]}`);
        if (out.size > 25) return [...out];
      }
    }
    return [...out];
  }

  function firstString(obj, keys) {
    for (const k of keys) {
      const v = obj?.[k];
      if (typeof v === "string" && v.trim()) return v.trim();
      if (v && typeof v === "object" && typeof v.text === "string" && v.text.trim())
        return v.text.trim();
    }
    return "";
  }

  function toDate(v) {
    if (!v) return "";
    // O Meta manda ora epoch em segundos, ora string ISO.
    const n = Number(v);
    if (Number.isFinite(n) && n > 1_000_000_000 && n < 4_000_000_000) {
      return new Date(n * 1000).toISOString().slice(0, 10);
    }
    if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v)) return v.slice(0, 10);
    return "";
  }

  function ingestPayload(text) {
    // Respostas GraphQL do Meta as vezes vem como varios objetos JSON
    // concatenados por quebra de linha, entao tentamos linha a linha.
    const chunks = text.includes("\n") ? text.split("\n") : [text];
    let added = 0;

    for (const chunk of chunks) {
      const trimmed = chunk.trim();
      if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) continue;
      let data;
      try {
        data = JSON.parse(trimmed);
      } catch (_) {
        continue;
      }

      walk(data, (obj) => {
        const id = findId(obj);
        if (!id) return;

        const snap = obj.snapshot && typeof obj.snapshot === "object" ? obj.snapshot : obj;
        const rawLink = firstString(snap, ["link_url", "linkUrl", "caption_link", "url"]);
        const finalUrl = unwrapFacebookLink(rawLink);

        const record = {
          id,
          url: finalUrl,
          host: hostOf(finalUrl),
          page: firstString(snap, ["page_name", "pageName"]),
          cta: firstString(snap, ["cta_text", "ctaText", "cta_type"]),
          title: firstString(snap, ["title", "link_description", "caption"]),
          body: firstString(snap, ["body", "text"]).slice(0, 400),
          start: toDate(obj.start_date ?? obj.startDate ?? snap.start_date),
          leaks: scanLeaks(JSON.stringify(obj).slice(0, 60_000)),
        };

        const prev = ads.get(id);
        // Um mesmo anuncio aparece em varios payloads; ficamos com a versao
        // mais rica em vez de sobrescrever com uma parcial.
        if (!prev || (!prev.url && record.url) || record.leaks.length > prev.leaks.length) {
          ads.set(id, { ...prev, ...record });
          added++;
        }
      });
    }
    if (added) render();
  }

  // --- fallback por DOM ------------------------------------------------------
  // Se o Meta trocar o transporte, ainda pegamos os links visiveis.
  function scrapeDom() {
    let added = 0;
    document.querySelectorAll('a[href*="l.php"], a[href*="l.facebook.com"]').forEach((a) => {
      const url = unwrapFacebookLink(a.href);
      const host = hostOf(url);
      if (isMetaHost(host)) return;
      const key = "dom:" + url;
      if (ads.has(key)) return;
      ads.set(key, {
        id: key,
        url,
        host,
        page: "",
        cta: (a.innerText || "").trim().slice(0, 40),
        title: "",
        body: "",
        start: "",
        leaks: scanLeaks(url),
        fromDom: true,
      });
      added++;
    });
    if (added) render();
  }

  // ===========================================================================
  // ANALISE
  // ===========================================================================

  /**
   * O achado nao e o dominio dominante — esse e a white page, ja sabido.
   * O achado e a cauda: variantes de teste, campanhas velhas, configuracao
   * incompleta. Marcamos como outlier tudo com <=2 anuncios ou <5% do total.
   */
  function analyze() {
    const counts = new Map();
    for (const ad of ads.values()) {
      if (!ad.host) continue;
      counts.set(ad.host, (counts.get(ad.host) || 0) + 1);
    }
    const total = [...counts.values()].reduce((a, b) => a + b, 0);
    const threshold = Math.max(2, Math.floor(total * 0.05));
    const rows = [...counts.entries()]
      .map(([host, n]) => ({ host, n, outlier: total > 8 && n <= threshold }))
      .sort((a, b) => b.n - a.n);
    return { rows, total, max: rows[0]?.n || 1 };
  }

  const leakingAds = () => [...ads.values()].filter((a) => a.leaks.length);

  // ===========================================================================
  // EXPORT
  // ===========================================================================

  function toCsv() {
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""').replace(/\r?\n/g, " ")}"`;
    const head = ["ad_id", "start", "host", "url", "cta", "title", "leaks", "body"];
    const lines = [head.join(",")];
    for (const a of ads.values()) {
      lines.push(
        [a.id, a.start, a.host, a.url, a.cta, a.title, a.leaks.join(" | "), a.body]
          .map(esc)
          .join(",")
      );
    }
    return lines.join("\n");
  }

  function download(filename, text, mime) {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ===========================================================================
  // AUTO-SCROLL
  // ===========================================================================

  function toggleScroll() {
    autoScroll = !autoScroll;
    stagnantTicks = 0;
    if (autoScroll) {
      let lastCount = ads.size;
      scrollTimer = setInterval(() => {
        window.scrollTo(0, document.body.scrollHeight);
        scrapeDom();
        if (ads.size === lastCount) {
          stagnantTicks++;
          // Tres ciclos sem anuncio novo = chegamos ao fim da lista.
          if (stagnantTicks >= 3) toggleScroll();
        } else {
          stagnantTicks = 0;
          lastCount = ads.size;
        }
        render();
      }, 1800);
    } else {
      clearInterval(scrollTimer);
      scrollTimer = null;
    }
    render();
  }

  // ===========================================================================
  // PAINEL
  // ===========================================================================

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; margin: 0; padding: 0; }

    .panel {
      position: fixed; right: 18px; bottom: 18px; z-index: 2147483647;
      width: 386px; max-height: 74vh; display: flex; flex-direction: column;
      background: #161a26;
      border: 1px solid #2b3244;
      border-radius: 3px;
      box-shadow: 0 18px 48px rgba(0,0,0,.55);
      font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace;
      font-size: 11px; line-height: 1.45; color: #aeb8cc;
    }

    .bar {
      display: flex; align-items: center; gap: 8px;
      padding: 9px 11px; border-bottom: 1px solid #2b3244;
      background: #1b2030; cursor: grab; user-select: none;
    }
    .dot { width: 6px; height: 6px; border-radius: 50%; background: #4a5568; }
    .dot.live { background: #f0a020; box-shadow: 0 0 7px #f0a020; }
    .name {
      font-size: 10px; letter-spacing: .13em; text-transform: uppercase;
      color: #e2e8f4; font-weight: 600; flex: 1;
    }
    .fold {
      background: none; border: none; color: #6b7688; cursor: pointer;
      font-size: 14px; padding: 0 3px; font-family: inherit;
    }
    .fold:hover { color: #e2e8f4; }

    .stats { display: flex; border-bottom: 1px solid #2b3244; }
    .stat { flex: 1; padding: 10px 11px; border-right: 1px solid #2b3244; }
    .stat:last-child { border-right: none; }
    .stat b { display: block; font-size: 19px; color: #e2e8f4; font-weight: 500; }
    .stat.alert b { color: #f0a020; }
    .stat span {
      font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: #5f6b80;
    }

    .scroll { overflow-y: auto; flex: 1; }
    .scroll::-webkit-scrollbar { width: 7px; }
    .scroll::-webkit-scrollbar-thumb { background: #2b3244; }

    .sect {
      padding: 8px 11px 4px; font-size: 9px; letter-spacing: .1em;
      text-transform: uppercase; color: #5f6b80;
      border-top: 1px solid #21273a;
    }

    .row { padding: 4px 11px 6px; }
    .row .top { display: flex; justify-content: space-between; gap: 8px; }
    .host { color: #aeb8cc; word-break: break-all; }
    .row.out .host { color: #f0a020; }
    .n { color: #5f6b80; flex-shrink: 0; }
    .track { height: 2px; background: #21273a; margin-top: 4px; }
    .fill { height: 100%; background: #48536b; }
    .row.out .fill { background: #f0a020; }
    .flag {
      font-size: 8px; letter-spacing: .1em; color: #f0a020;
      border: 1px solid #6b4c14; padding: 0 3px; margin-left: 5px;
    }

    .leak {
      margin: 3px 11px 5px; padding: 7px 8px;
      background: #241d0e; border-left: 2px solid #f0a020;
    }
    .leak code { color: #f0c060; display: block; word-break: break-all; }
    .leak a { color: #6b7688; text-decoration: none; font-size: 9px; }
    .leak a:hover { color: #f0a020; }

    .empty { padding: 14px 11px; color: #4a5568; }

    .acts {
      display: grid; grid-template-columns: 1fr 1fr;
      gap: 1px; background: #2b3244; border-top: 1px solid #2b3244;
    }
    .acts button {
      background: #1b2030; border: none; color: #aeb8cc; cursor: pointer;
      padding: 8px 6px; font-family: inherit; font-size: 10px;
      letter-spacing: .06em; text-transform: uppercase;
    }
    .acts button:hover { background: #232a3d; color: #e2e8f4; }
    .acts button.on { background: #f0a020; color: #161a26; font-weight: 600; }
    .acts button.wide { grid-column: 1 / -1; }
    .folded .scroll, .folded .stats, .folded .acts { display: none; }
  `;

  function build() {
    const host = document.createElement("div");
    host.id = "alh-host";
    // Shadow DOM: o CSS do Facebook e agressivo e mudaria a cada deploy.
    // Isolar garante que o painel fique identico para sempre.
    root = host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = CSS;
    root.append(style);
    const panel = document.createElement("div");
    panel.className = "panel";
    root.append(panel);
    document.documentElement.append(host);
    return panel;
  }

  function render() {
    if (!root) return;
    const panel = root.querySelector(".panel");
    const folded = panel.classList.contains("folded");
    const { rows, max } = analyze();
    const leaks = leakingAds();

    panel.innerHTML = `
      <div class="bar">
        <div class="dot ${autoScroll ? "live" : ""}"></div>
        <div class="name">Ad Library Harvest</div>
        <button class="fold">${folded ? "+" : "\u2212"}</button>
      </div>
      <div class="stats">
        <div class="stat"><b>${ads.size}</b><span>anuncios</span></div>
        <div class="stat"><b>${rows.length}</b><span>dominios</span></div>
        <div class="stat ${leaks.length ? "alert" : ""}"><b>${leaks.length}</b><span>vazamentos</span></div>
      </div>
      <div class="scroll">
        ${
          leaks.length
            ? `<div class="sect">Vazamentos</div>` +
              leaks
                .slice(0, 30)
                .map(
                  (a) => `
              <div class="leak">
                <code>${esc(a.leaks.join("  \u00b7  "))}</code>
                <a href="https://www.facebook.com/ads/library/?id=${esc(a.id)}"
                   target="_blank" rel="noreferrer">abrir anuncio ${esc(a.id)} \u2197</a>
              </div>`
                )
                .join("")
            : ""
        }
        <div class="sect">Dominios de destino</div>
        ${
          rows.length
            ? rows
                .map(
                  (r) => `
            <div class="row ${r.outlier ? "out" : ""}">
              <div class="top">
                <span class="host">${esc(r.host)}${
                    r.outlier ? '<span class="flag">OUTLIER</span>' : ""
                  }</span>
                <span class="n">${r.n}</span>
              </div>
              <div class="track"><div class="fill" style="width:${(r.n / max) * 100}%"></div></div>
            </div>`
                )
                .join("")
            : `<div class="empty">Nenhum destino ainda. Ligue a varredura ou role a lista de anuncios.</div>`
        }
      </div>
      <div class="acts">
        <button class="wide ${autoScroll ? "on" : ""}" data-a="scroll">
          ${autoScroll ? "Parar varredura" : "Varrer todos os anuncios"}
        </button>
        <button data-a="csv">CSV</button>
        <button data-a="json">JSON</button>
        <button data-a="copy">Copiar dominios</button>
        <button data-a="clear">Limpar</button>
      </div>`;

    if (folded) panel.classList.add("folded");
    panel.querySelector(".fold").onclick = () => {
      panel.classList.toggle("folded");
      render();
    };
    panel.querySelectorAll("[data-a]").forEach((btn) => {
      btn.onclick = () => act(btn.dataset.a, btn);
    });
  }

  function act(action, btn) {
    if (action === "scroll") return toggleScroll();
    if (action === "csv")
      return download(`adlib_${Date.now()}.csv`, toCsv(), "text/csv;charset=utf-8");
    if (action === "json")
      return download(
        `adlib_${Date.now()}.json`,
        JSON.stringify([...ads.values()], null, 2),
        "application/json"
      );
    if (action === "copy") {
      const list = analyze().rows.map((r) => `${r.host}\t${r.n}${r.outlier ? "\tOUTLIER" : ""}`);
      navigator.clipboard.writeText(list.join("\n")).then(() => {
        btn.textContent = "Copiado";
        setTimeout(render, 1200);
      });
      return;
    }
    if (action === "clear") {
      ads.clear();
      render();
    }
  }

  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  // ===========================================================================
  // BOOT
  // ===========================================================================
  window.addEventListener("ALH_PAYLOAD", (e) => {
    try {
      ingestPayload(e.detail.text);
    } catch (err) {
      console.debug("[ALH] payload ignorado", err);
    }
  });

  build();
  render();
  scrapeDom();
  new MutationObserver(() => scrapeDom()).observe(document.body, {
    childList: true,
    subtree: true,
  });

  console.debug("[ALH] painel pronto");
})();
