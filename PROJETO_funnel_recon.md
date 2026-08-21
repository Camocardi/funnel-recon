# Funnel Recon — Brief de Projeto

Ferramenta de reconhecimento competitivo para anúncios do Meta. Recebe o link de
uma página na Biblioteca de Anúncios e tenta, de forma automática e em cascata,
reconstruir o que o anúncio realmente faz: para onde o link vai de verdade
(**cloaker de destino**) e o que o criativo realmente mostra no feed
(**cloaker de criativo**).

Este documento é o contexto para desenvolver o projeto no Claude Code.
Uso pessoal, pesquisa competitiva.

## Filosofia de construção

A meta é uma ferramenta **completa**, construída **aos poucos**. Cada módulo
roda e é útil sozinho, na linha de comando, antes de ser plugado na cascata e
antes de ganhar interface visual. Nada aqui precisa ser feito de uma vez — o
documento descreve o destino final, mas a seção 11 (ordem de construção) diz por
onde começar para ter valor a cada passo. Prefira sempre um módulo pequeno que
funciona hoje a meia arquitetura que só funciona no fim.

Leia inteiro antes de codar. As seções 2 e 5 evitam construir na direção errada.

---

## 1. O problema

Anunciantes usam **cloaking** para mostrar uma coisa ao Meta (revisão +
Biblioteca) e outra ao usuário real no feed. Há dois tipos independentes, que
podem aparecer juntos ou separados:

**Cloaker de DESTINO** — esconde *para onde o link vai*.
O mesmo link entrega uma página inócua ("white page", ex: loja genérica) para
quem parece revisor/bot, e a página real ("money page", tipicamente funil de
Telegram/WhatsApp) para quem parece o público comprador. O criativo na
Biblioteca é honesto; o destino é que muda conforme quem clica.

**Cloaker de CRIATIVO** — esconde *o que o anúncio mostra*.
O revisor e a Biblioteca veem um vídeo/imagem comportado. O usuário no feed
recebe outro criativo, o de verdade — muitas vezes o que violaria política. O
anúncio "aprovado" que aparece na Biblioteca não é o que roda.

O objetivo do projeto é reconstruir ambos: o destino real e o criativo real.

---

## 2. A verdade física que define todo o resto — LEIA ISTO

Existe uma diferença estrutural entre os dois tipos, e ela define o que é
possível automatizar.

### Cloaker de destino — o adversário responde a você
A decisão é **server-side no servidor do anunciante**. Ele escolhe qual página
mandar antes de qualquer byte sair, com base em:

1. **IP / ASN** (geo, datacenter vs residencial vs móvel, blacklists) ← decisivo
2. TLS fingerprint (JA3/JA4 do handshake)
3. Headers (User-Agent, Accept-Language, ordem dos headers)
4. Referrer + `fbclid` (veio do Facebook? token válido?)
5. Fingerprint JS (canvas, WebGL, touch, timezone × geo do IP)
6. Comportamento (mouse, tempo na página)

Como **nós controlamos a requisição**, dá para atacar: mudar IP, headers, TLS e
pedir de novo com outra "persona". O adversário responde para nós. O que NÃO dá
para mudar por software é a camada 1 — nenhuma linha de código muda de qual IP
o pacote sai. Todo "quebrador de cloaker" vendido por aí é, no fundo, uma
**frota de IPs** (proxy móvel/residencial ou devices reais) embalada. A "quebra"
é comprar o IP certo, não escrever o algoritmo certo.

### Cloaker de criativo — quem serve é o Meta
Aqui a mídia é entregue pela **infraestrutura do próprio Meta**, não pelo
anunciante. A Biblioteca puxa da versão em revisão; o feed puxa da entrega. Você
**não consegue "pedir de novo com outra persona"** — o objeto que a Biblioteca
expõe é o único que a API do Meta te dá. Não há requisição sua para variar. A
única forma de ver o criativo real é observá-lo **sendo entregue num feed real**,
no país/device/conta do público. Exceção importante: quando o criativo carrega
mídia de um **domínio de terceiro**, esse arquivo volta a ser servido pelo
anunciante — e aí recai na técnica de cloaker de destino, que a gente ataca.

### Consequência para o projeto
Isto **não é um quebrador**. É um **orquestrador honesto**: automatiza o
reconhecimento, tenta N caminhos em ordem de custo crescente, e quando bate na
parede física (precisa de IP real no país, ou precisa observar o feed real) ele
**diz isso com clareza** em vez de fingir que resolve. As camadas de código são
as fáceis; o gargalo é acesso — ao IP certo e ao feed real —, e isso é serviço
pago / presença humana, não programação.

---

## 3. O que já fizemos nesta investigação — e o resultado

Caso real: página "Ana Alves", ~120-233 anúncios. Foco em **cloaker de destino**.
Três frentes, cada uma resolvendo uma parte.

### 3.1 OSINT (reconhecimento passivo) — eliminou hipóteses
- Busca do domínio na web: zero pegada → domínio descartável, confirmou cloaking
- **urlscan.io**: 0 scans → ninguém tinha capturado ainda
- **crt.sh** (`%25dominio` = wildcard, pega subdomínios): caiu (502); via JSON
  (`?output=json`) e CertSpotter API são fallbacks mais estáveis
- **Wayback** via UI deu timeout; a **CDX API**
  (`/cdx/search/cdx?url=DOMINIO*&output=text`) é texto puro e não trava
- **Transparência da Página** (aba "Sobre" na Biblioteca): 5 seguidores, sem
  posts, sem foto, nome nunca alterado, admins no Brasil, criada 07/2024 →
  página-casca envelhecida, operação BR mirando fora
- **Lookup de subdomínio**: só `web` e `www`, primeiros vistos em março/2026

Nada achou o funil, mas cada "não" estreitou o problema.

### 3.2 Extensão de Biblioteca (coleta) — VIROU O JOGO
Extensão Chrome MV3 que **intercepta o tráfego GraphQL** da Biblioteca (não
raspa DOM — o DOM do Meta é ofuscado e muda a cada deploy; a API interna é
estável e traz campos que a UI nem renderiza).

236 anúncios capturados, agrupados por domínio:
- `achadaspremium.shop` — 132 (a **white page**, genérica de e-commerce)
- `cantinhoprivado.shop` — 67 (o **segundo funil**, nome que combina com a
  oferta — aqui estava a carne)
- vazios / `transparency.meta.com` — ruído (falso positivo do fallback de DOM)

**Descoberta decisiva:** a coluna `url` do CSV exportado continha a URL REAL com
caminho e `fbclid`, que a UI não mostra:
```
https://cantinhoprivado.shop/l/ab68b001?fbclid=IwcGRvZ...
```
`/l/<hash>` é padrão de redirecionador de tracker. Passamos rodadas testando a
raiz do domínio (404) sem perceber que a URL real estava no CSV.

**Lição central:** a informação valiosa está no PAYLOAD/EXPORT, não na tela.
Sempre extraia e inspecione o dado bruto.

### 3.3 Probe de personas (teste de acesso) — diagnóstico
Script Python que dispara a MESMA URL com várias personas (TLS + headers +
referrer) e compara respostas por hash.

Achados na URL certa:
- TLS cru (`python-requests`, sem impersonate) → **403 Cloudflare**. Há **WAF na
  frente do cloaker**.
- Imitando navegador real (`curl_cffi impersonate`) → passaram o WAF.

Diagnóstico: todas as personas iguais → filtro é IP/geo (só proxy resolve).
Variam → filtro lê header/TLS/referrer (dá pra ajustar). Isola a variável com
pares de controle (ex: pt-BR vs en-US, só muda o idioma).

### 3.4 Desfecho
Com a URL completa (`/l/<hash>` + `fbclid`) no probe, chegou-se ao funil. O
gargalo nunca foi falta de ferramenta — foi testar o endereço errado. Sequência
correta: **coletar certo → achar a URL real no dado → testar do jeito certo**.

---

## 4. Erros que cometemos (para o app evitar)

Codifique como comportamento do orquestrador:

1. **Testar a raiz do domínio em vez da URL real.** Usar sempre a URL completa
   com path + `fbclid`. Raiz de tracker dá 404 — normal, NÃO é site fora do ar
   nem cloaker bloqueando.
2. **Confundir 404/erro com "cloaker filtrando tudo igual".** 4xx/5xx é idêntico
   para toda persona por definição. Veredito de "filtro por IP" só vale sobre
   respostas 200. Guarda: se tudo é erro → URL provavelmente errada.
3. **Confundir desafio de WAF (Cloudflare 403/503) com resposta do cloaker.**
   Camadas diferentes. Separe antes de comparar.
4. **Fallback de DOM capturando links internos do Meta**
   (`transparency.meta.com`, `facebook.com`). Sempre filtrar domínios do Meta.
5. **Heurística de outlier disparando com poucos dados.** Só marcar outlier com
   volume mínimo (ex: >8 anúncios).
6. **Assumir rotação de domínio a partir de 1 domínio dominante.** Dois domínios
   em paralelo = dois funis simultâneos, não rotação.
7. **`fbclid` pode ser de uso único** e já queimado quando capturado. Se o
   cloaker valida em tempo real, click ID reciclado falha. Muitos só checam se o
   parâmetro existe. Vale tentar, não confie.

---

## 5. Cloaker de criativo — métodos e o que dá para fazer

Os três métodos que produzem "Biblioteca ≠ feed", e a dificuldade de cada um:

| Método | Como funciona | Dá pra ver o real? | Como | Dificuldade |
|---|---|---|---|---|
| **Mídia externa** | O player do criativo carrega vídeo/imagem de um domínio de terceiro, que faz cloaking no próprio arquivo | **Sim** | Interceptar a URL do asset e rodar probe+proxy nela, igual ao cloaker de destino | **Média** — reusa o que já temos |
| **Bait-and-switch** | Aprovam criativo limpo, depois editam; a entrega passa a usar outro asset | Parcial | Capturar o criativo entregue no feed e comparar com o da Biblioteca; monitorar mudança no tempo | Alta |
| **Criativo dinâmico** | O "vídeo" é montado na entrega a partir de fonte que o anunciante controla, variando por geo/device | Quase não | Só observando a entrega real no device/geo/conta certos | Muito alta — é clique/feed humano |

Padrão que se repete do caso de destino: **a parte automatizável é a de mídia
externa** — encaixa direto no orquestrador, aplicando o estágio de probe+proxy à
URL do asset em vez da URL de destino. As outras duas exigem **observar a
entrega real**, ou seja, olho num feed real no país/device/conta do público. A
Biblioteca não carrega essa informação; não se extrai o que não está no dado.

### Como detectar que há cloaking de criativo
Mesmo sem "quebrar", dá para **detectar** e medir, o que já tem valor:
- **Capturar o criativo entregue no feed** via a mesma interceptação de rede,
  mas rodando na navegação normal do Facebook (não na Biblioteca) — precisa de
  sessão real no feed (extensão enquanto a pessoa scrolla, ou device/proxy no
  país).
- **Comparar por hash perceptual (pHash)** o vídeo/imagem da Biblioteca vs o do
  feed. Divergência acima de um limiar = cloaking de criativo. pHash (não hash
  exato) porque recompressão muda os bytes sem mudar a imagem — hash exato daria
  falso positivo.
- **Detectar asset de domínio de terceiro** no criativo → manda essa URL pro
  estágio de probe+proxy que já existe.

---

## 6. Arquitetura proposta

Pipeline de estágios em cascata. Cada estágio custa mais (tempo/dinheiro) que o
anterior; para no primeiro que resolve. O CÉREBRO é o classificador (white vs
money page; criativo limpo vs real) e o orquestrador que decide quando escalar.

```
                  link da Biblioteca de Anúncios
                             |
              +--------------v---------------+
              | [1] COLETOR                  |  todos anúncios (ativo+inativo,
              |     intercepta GraphQL/API   |  por país), domínios + URLs reais
              |     + captura criativo feed  |  + fbclid + assets de criativo
              +--------------+---------------+
                             |
        +--------------------+--------------------+
        | TRILHA DESTINO     |     TRILHA CRIATIVO |
        v                    |                     v
+---------------+            |           +--------------------+
| [2] OSINT     |            |           | [5c] COMPARADOR    |
| urlscan/crt.sh|            |           | pHash Biblio x feed|
| wayback/whois |            |           | -> tem cloaking?   |
+------+--------+            |           +---------+----------+
       | (nao achou)         |                     | (asset externo?)
       v                     |                     v
+---------------+            |           +--------------------+
| [3] PROBE     |            |           | manda URL do asset |
| seu IP        |            |           | para [3]/[4]       |
+------+--------+            |           +--------------------+
       | (tudo branco/WAF)   |
       v                     |
+----------------+           |
| [4] PROBE+PROXY|           |
| pais-alvo(pago)|           |
+------+---------+           |
       | (ainda branco)      |
       v                     |
+----------------+           |
| [5] BROWSER    |           |
| REAL + proxy   |           |
| (fingerprint JS)|          |
+------+---------+           |
       +----------+----------+
                  v
       +------------------------+
       | [6] CLASSIFICADOR +    |  destino: white vs money page
       |     RELATORIO honesto  |  criativo: limpo vs real / divergencia
       |                        |  se nao chegou: "falta IP no pais X" ou
       |                        |  "falta observar feed real" — sem prometer
       +------------------------+
```

### Módulos

**[1] Coletor.** Hoje é a extensão Chrome (intercepta `fetch`/`XHR` no GraphQL
da Biblioteca). Para automação total: (a) manter a extensão exportando JSON que
a pipeline consome; (b) API oficial da Ad Library (mais estável, mas fora da UE
só cobre anúncios políticos — provável limitação); (c) Playwright abrindo a
Biblioteca e capturando as mesmas respostas. Deve coletar ativos E inativos
(`active_status`) e por país (`country=BR`, `country=US`…). **Comparar conjuntos
por país é o atalho mais barato:** se o funil roda no SEU país, você clica sem
proxy. Nova responsabilidade: **capturar também o criativo entregue no feed**
(navegação normal do FB) para alimentar a trilha de criativo.
Saída normalizada por anúncio: `ad_id, start_date, country, display_host,
full_url (path+fbclid), cta, title, body, leaks[], creative_lib_url,
creative_feed_url, creative_asset_hosts[]`.

**[2] OSINT.** Por domínio, em paralelo: urlscan (scans existentes → screenshot
+ redirect chain), crt.sh `?output=json` (fallback CertSpotter) → subdomínios,
Wayback CDX API → snapshots antigos, WHOIS/DNS reverso → outros domínios do dono.
Baixa dificuldade, alto retorno. **Comece por ele.**

**[3] Probe.** Já existe (`cloaker_probe.py`). N personas, compara por hash
normalizado (remover nonces/timestamps antes de hashear). Guardas: se tudo
4xx/5xx → URL errada; separar WAF da comparação. Varre sinais de money page:
`t.me/`, `wa.me/`, `tg://`, handles `*bot`, pixel (`fbq('init'`), params de
tracker (kclickid/keitaro/binom/redtrack). Serve às duas trilhas: destino e
asset de criativo externo.

**[4] Probe + proxy.** Mesmo motor, `proxies=`. AQUI está o dinheiro: proxy
móvel/residencial no país-alvo (IPRoyal/Soax/Bright Data, ~US$5-15/GB). País-alvo
vem de [1]. Sem isto, se o filtro for geo, nada avança — e o app deve dizer.

**[5] Browser real.** Camada JS de fingerprint (canvas/WebGL/touch) → `curl_cffi`
não basta. Camoufox ou Patchright headless, atrás do mesmo proxy. Só acionar se
[4] ainda retornar white page com o IP certo.

**[5c] Comparador de criativo.** pHash do criativo da Biblioteca vs do feed;
divergência = cloaking de criativo. Detecta asset de domínio terceiro e
encaminha a URL para [3]/[4]. Depende de [1] ter capturado o criativo do feed.

**[6] Classificador + relatório.** O cérebro. Destino: baseline = página que a
maioria recebe (white); sinais de funil, redirect JS, mudança de tamanho vs
baseline → money page. Criativo: divergência de pHash acima do limiar. Se nenhum
estágio resolveu: relatório honesto — "caminhos automáticos esgotados; filtro é
geo/comportamental; falta clique humano no país X (~US$20 num freelancer)" ou
"criativo real só visível observando o feed no país X".

---

## 7. Stack sugerida

- **Backend:** Python (já temos os módulos). Node só para manter a extensão.
- **HTTP com fingerprint:** `curl_cffi` (imita JA3 de Chrome/Safari reais).
- **Browser stealth:** Camoufox ou Patchright.
- **Mídia/pHash:** `Pillow` + `imagehash` para imagem; para vídeo, extrair
  keyframes com `ffmpeg` e aplicar pHash nos frames.
- **Orquestração:** asyncio/httpx — [2] e [3] paralelizam bem.
- **Proxy:** provider com API, abstraído atrás de uma interface `ProxyProvider`
  para trocar de fornecedor sem tocar no resto.
- **Frontend (a parte visual):** cola o link, acompanha a pipeline estágio a
  estágio (spinner por estágio), no fim mostra histograma de domínios + sinais
  de vazamento + divergência de criativo + veredito. FastAPI + página única, ou
  desktop. **Só depois que a pipeline roda por linha de comando.**
- **Persistência:** SQLite. Guardar cada scan permite comparar campanhas ao
  longo do tempo (a Biblioteca não deixa — anúncio comercial some ao pausar).

---

## 8. Limites e manutenção (expectativas realistas)

- **O Meta muda o schema do GraphQL** periodicamente. O coletor quebra e precisa
  de ajuste. Camada de captura "burra" (só pega o bruto) separada da de parsing,
  para consertar num lugar só.
- **Anúncio comercial some da Biblioteca ao pausar** (fora da UE não há arquivo).
  Só dá pra capturar o ativo agora — por isso persistir tem valor.
- **A camada de IP é serviço pago e é o gargalo real** do cloaker de destino.
- **Ver o criativo real exige observar o feed real** — não há atalho de dado.
- **`fbclid` de uso único** pode falhar se validado em tempo real.
- Estas técnicas (OSINT, fingerprint, browser stealth, pHash) são as de
  segurança ofensiva/bug bounty; a diferença está no uso. Mantenha para uso
  próprio.

---

## 9. Ativos que já existem (reaproveitar, não reescrever)

- **`cloaker_probe.py`** — motor de personas do estágio [3]. Já tem: escada de
  fallback de impersonate por versão do curl_cffi, guarda de status 4xx/5xx,
  detecção de desafio Cloudflare separada, varredura de sinais de money page,
  normalização antes do hash.
- **Extensão `adlib-harvester`** (manifest + inject.js + content.js) — o estágio
  [1]. Já tem: interceptação fetch/XHR no GraphQL, unwrap de
  `l.facebook.com/l.php`, walk de JSON schema-agnóstico, detecção de vazamentos,
  histograma com outliers, export CSV/JSON, auto-scroll. Correções pendentes:
  filtrar domínios do Meta no fallback de DOM; piso mínimo para marcar outlier.

---

## 10. Schema de dados (contrato entre módulos)

Definir cedo, porque todo módulo lê/escreve isto. Sugestão inicial (SQLite/JSON):

```
ad:
  ad_id            texto  (chave)
  page_id          texto
  start_date       data
  countries        lista  (onde veicula, se disponível)
  display_host     texto  (domínio exibido no criativo)
  full_url         texto  (destino real com path + fbclid)
  cta, title, body texto
  leaks            lista  (t.me/wa.me/bot/pixel/tracker achados)
  creative_lib_url texto  (asset como está na Biblioteca)
  creative_feed_url texto (asset como entregue no feed, se capturado)
  asset_hosts      lista  (domínios de onde a mídia carrega)

scan_result:  (uma linha por tentativa de estágio)
  ad_id, stage, persona/proxy, status, body_sha, final_url,
  signals[], verdict (white|money|challenge|error|unknown), ts

creative_diff:
  ad_id, phash_lib, phash_feed, distance, is_cloaked (bool)
```

---

## 11. Ordem de construção recomendada

Não construa tudo de uma vez. Cada passo entrega algo útil sozinho.

1. **[2] OSINT** — baixa dificuldade, APIs públicas. Recebe lista de domínios,
   devolve relatório de exposição. Teria economizado metade das idas e vindas.
2. **Normalizar [1]** — extensão/coletor cospe JSON limpo no schema da seção 10.
3. **Integrar [3]** — o probe já existe; encaixar lendo o JSON do [1].
4. **[6] Classificador** (versão simples: busca de sinais + comparação com
   baseline). É o que transforma dados em resposta.
5. **[5c] Comparador de criativo** — quando quiser cobrir o segundo tipo de
   cloaker. Precisa de [1] capturando o criativo do feed.
6. **Frontend** — só depois que a pipeline roda ponta a ponta por CLI.
7. **[4]/[5] proxy e browser real** — por último; dependem de serviço pago e só
   valem com o resto sólido.

Regra geral: cada estágio roda e é testável SOZINHO antes de entrar na cascata.
O orquestrador é a última peça, não a primeira.

---

## 12. Primeiro comando sugerido no Claude Code

> "Leia PROJETO_funnel_recon.md. Vamos começar pelo módulo [2] OSINT: um script
> Python que recebe uma lista de domínios e, para cada um, consulta em paralelo
> urlscan.io, crt.sh (output=json com fallback CertSpotter), Wayback CDX API e
> WHOIS, e devolve um relatório dizendo se o funil já está exposto em algum lugar
> (screenshot/redirect no urlscan, subdomínio revelador no crt.sh, snapshot
> antigo no wayback). Estrutura modular, cada fonte numa função, async, com
> tratamento de erro por fonte (uma falhar não derruba as outras). Escreva a
> saída no schema de `scan_result`/`ad` da seção 10 para já servir de contrato."
