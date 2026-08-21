# Ad Library Harvester

Extensão Chrome que coleta o destino de **todos** os anúncios de uma página na
Biblioteca de Anúncios do Meta, agrupa por domínio e destaca o que destoa.

Não quebra cloaker. Cloaker é decisão server-side — nada rodando no seu navegador
muda de qual IP o pacote sai. O que isto faz é encontrar o anúncio que **não
precisa** ser desbloqueado: a variante antiga, o domínio de teste, o criativo
onde o `@` do bot escapou pro texto.

## Instalar

1. `chrome://extensions`
2. Ative **Modo do desenvolvedor** (canto superior direito)
3. **Carregar sem compactação** → selecione esta pasta
4. Abra a Biblioteca de Anúncios. O painel aparece embaixo à direita.

## Usar

1. Abra a página do anunciante na Biblioteca
2. Clique em **Varrer todos os anúncios** — ele rola sozinho e para quando a
   lista acaba
3. Leia o painel:
   - **Vazamentos** — `t.me`, `wa.me`, handles de bot, IDs de pixel e parâmetros
     de tracker encontrados em qualquer campo do anúncio
   - **Domínios de destino** — histograma. O de cima é a white page.
     Os marcados **OUTLIER** são o alvo.
4. Exporte CSV ou JSON

## Onde olhar

O domínio dominante já é conhecido e não interessa. O valor está na cauda:
domínio com 1 ou 2 anúncios costuma ser teste antigo ou campanha encerrada —
e cloaker de campanha morta frequentemente ficou mal configurado, servindo a
money page para qualquer um.

Cruze com a coluna `start` do CSV: **outlier + data mais antiga** é a melhor
aposta da lista.

## Como funciona

`inject.js` roda no contexto da página e envolve `fetch` e `XMLHttpRequest`
para capturar as respostas GraphQL que alimentam a Biblioteca. Os dados vêm
estruturados, incluindo campos que a interface nem renderiza.

`content.js` roda isolado, percorre o JSON sem depender do schema (o Meta muda
nomes de campo com frequência), desembrulha os redirects `l.facebook.com/l.php`,
roda os padrões de vazamento e desenha o painel em Shadow DOM.

Raspagem de DOM existe como fallback: se o Meta trocar o transporte, os links
visíveis ainda são coletados.

## Limites

- Só a Biblioteca de Anúncios (`facebook.com/ads/library*`)
- Faça login antes — deslogado, a Biblioteca esconde metade dos campos
- Se a captura vier vazia, abra o console (F12) e veja se `[ALH] interceptador
  ativo` apareceu. Se não, o Meta mudou a rota; ajuste `isTarget()` em `inject.js`
- Se um dia precisar de volume sério, existe API oficial da Ad Library — mais
  estável que qualquer interceptação
