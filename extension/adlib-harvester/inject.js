/**
 * inject.js — roda no MAIN world (mesmo contexto JS da pagina).
 *
 * Por que interceptar rede em vez de raspar o DOM:
 * a Biblioteca de Anuncios e React com nomes de classe ofuscados que mudam a
 * cada deploy do Meta. Qualquer seletor de CSS quebra em semanas. Ja o payload
 * GraphQL que alimenta esses componentes carrega os dados estruturados e
 * limpos — inclusive campos que a UI nem chega a renderizar.
 *
 * Aqui nao ha parsing: so capturamos o texto bruto e empurramos por
 * CustomEvent para o content.js, que roda isolado. Manter esta camada burra
 * significa que mudanca de schema do Meta so exige mexer em um arquivo.
 */

(() => {
  "use strict";

  const CHANNEL = "ALH_PAYLOAD";
  const isTarget = (url) =>
    typeof url === "string" &&
    (url.includes("/api/graphql") || url.includes("/ads/library/async"));

  const emit = (text, source) => {
    // Payloads grandes travam a serializacao do evento; a Biblioteca costuma
    // devolver 50-400 KB por pagina, entao damos folga mas cortamos absurdos.
    if (!text || text.length > 8_000_000) return;
    try {
      window.dispatchEvent(
        new CustomEvent(CHANNEL, { detail: { text, source } })
      );
    } catch (_) {
      /* evento nao serializavel — ignora */
    }
  };

  // ---- fetch ---------------------------------------------------------------
  const nativeFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await nativeFetch.apply(this, args);
    try {
      const url =
        typeof args[0] === "string" ? args[0] : args[0] && args[0].url;
      if (isTarget(url)) {
        // clone() e obrigatorio: ler o body original consumiria o stream
        // e a pagina renderizaria vazio.
        response
          .clone()
          .text()
          .then((t) => emit(t, "fetch"))
          .catch(() => {});
      }
    } catch (_) {}
    return response;
  };

  // ---- XMLHttpRequest ------------------------------------------------------
  // O Meta ainda usa XHR em partes da paginacao, entao os dois caminhos importam.
  const nativeOpen = XMLHttpRequest.prototype.open;
  const nativeSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__alhUrl = url;
    return nativeOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (...args) {
    if (isTarget(this.__alhUrl)) {
      this.addEventListener("load", () => {
        try {
          if (this.responseType === "" || this.responseType === "text") {
            emit(this.responseText, "xhr");
          }
        } catch (_) {}
      });
    }
    return nativeSend.apply(this, args);
  };

  console.debug("[ALH] interceptador ativo");
})();
