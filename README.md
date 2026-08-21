# Funnel Recon

Reconhecimento competitivo de anúncios do Meta. O brief completo está em
[PROJETO_funnel_recon.md](PROJETO_funnel_recon.md) — leia antes de mexer.

## Estado atual

| Estágio | O que é | Situação |
|---|---|---|
| App | interface web local + `.app` pra clicar | **pronto** |
| Orquestrador | a cascata da §6 ponta a ponta | **pronto** |
| [1] Coletor | navegador controlado (extensão vira opcional) | **pronto** |
| [2] OSINT | pegada pública do domínio | **pronto** |
| [3] Probe | personas TLS/headers, com as guardas da §4 | **pronto** |
| [3b] Portas laterais | apex + inventário do CMS quando o filtro barra | **pronto** |
| [3c] Origem | diagnóstico: cloaker na borda (CDN) ou no servidor final | **pronto** (bypass ativo é manual) |
| [5c] Comparador de criativo | pHash Biblioteca × feed e no tempo | **pronto** |
| [4] Probe+proxy | mesmo motor, IP no país-alvo | não começado (depende de serviço pago) |
| [5] Browser real | fingerprint JS | não começado |
| [6] Classificador | white × money page | não começado |

## Usar (modo normal)

Clique duas vezes em **Funnel Recon.app**. Ele abre a interface no navegador.
Cole o link de uma página na Biblioteca de Anúncios e clique em Analisar.

Duas escolhas na tela, e elas mudam o que custa:

| O que analisar | O que roda | O que evita |
|---|---|---|
| **Funil e criativos** | tudo | — |
| **Só o funil** | OSINT + probe | não baixa imagem nenhuma |
| **Só os criativos** | pHash dos criativos | **não toca no site do alvo** — o IP de casa não é exposto a ele |

E **quantos anúncios** coletar: 100, 200, 300, 500, 1000 ou 2000. Número menor
termina mais rápido. Para página muito grande, filtre a busca na própria
Biblioteca (por país, por palavra) em vez de aumentar o teto — o motivo está
nas notas de campo.

Na primeira coleta, uma janela do Chromium abre e pede login no Facebook.
Faça o login ali dentro — a sessão fica guardada em `data/browser_profile/`
e isso não se repete.

## Instalar

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

## Usar

### Linha de comando (opcional — o app faz tudo isso)

```bash
# abrir a interface (o mesmo que clicar no .app)
./.venv/bin/python -m funnel_recon app

# ou os estágios isolados, para depurar um deles:
# varra a página com a extensão, exporte CSV, e importe:
./.venv/bin/python -m funnel_recon import ~/Downloads/adlib.csv

# 2. o import diz qual URL sondar primeiro; copie e rode:
./.venv/bin/python -m funnel_recon probe "https://alvo.shop/l/ab68b001?fbclid=..."

# 3. em paralelo, a pegada pública dos domínios que apareceram:
./.venv/bin/python -m funnel_recon osint alvo.shop outro.shop
```

### Comandos

```bash
# um ou vários domínios (aceita URL, extrai o host)
./.venv/bin/python -m funnel_recon osint cantinhoprivado.shop achadaspremium.shop

# a partir do export do coletor [1], ou de um .txt com um domínio por linha
./.venv/bin/python -m funnel_recon osint --from-file ads.json

# só uma fonte, sem gravar no banco, salvando o bruto
./.venv/bin/python -m funnel_recon osint alvo.shop --sources rdap --no-db --json out.json
```

Opcional: `export URLSCAN_API_KEY=...` sobe o limite de requisições do urlscan.

```bash
# [5c] comparar o criativo ENTREGUE no feed com o aprovado na Biblioteca
# (rola o seu feed logado; rode a análise de uma página no app antes)
./.venv/bin/python -m funnel_recon feed
./.venv/bin/python -m funnel_recon feed --page-id 1234567 --max-posts 200
```

```bash
# probe: personas TLS/headers contra a URL REAL (com caminho e fbclid)
./.venv/bin/python -m funnel_recon probe "https://alvo.shop/l/hash?fbclid=..."
./.venv/bin/python -m funnel_recon probe URL --proxy socks5://user:pass@host:porta
```

Rodar os testes (sem rede, segundos):
```bash
./.venv/bin/python tests/test_units.py
./.venv/bin/python tests/test_pipeline.py   # gabarito do caso Ana Alves
```

## Estrutura

```
funnel_recon/
  schema.py     contrato de dados da seção 10 do brief
  db.py         SQLite — anúncio some da Biblioteca ao pausar, então persistir é o ponto
  signals.py    padrões de money page, compartilhados entre [2], [3] e [6]
  report.py     relatório de terminal, incluindo correlação entre domínios
  cli.py        `python -m funnel_recon <comando>`
  osint/        urlscan · crt.sh (fallback CertSpotter) · Wayback CDX · RDAP+DNS
extension/adlib-harvester/   estágio [1]
legacy/cloaker_probe.py      estágio [3], aguardando integração
~/Library/Application Support/FunnelRecon/
  venv/            ambiente Python (`.venv` na pasta é só um atalho pra cá)
  data/scans.db    banco
  data/app.log     log do app
  browser_profile/ sessão do Facebook
```

## Notas de campo

- **WHOIS morreu.** A ICANN aposentou o serviço em 01/05/2026. O binário `whois`
  ainda responde, mas para vários TLDs devolve o registro do **próprio TLD**: em
  teste real, `whois cantinhoprivado.shop` reportou criação em 2016 (data do
  registro `.shop`, não do domínio). Usamos RDAP; `whois` ficou como fallback,
  com guarda que descarta resposta de TLD. Idade errada é pior que idade ausente.
- **crt.sh cai com frequência.** O fallback CertSpotter é acionado sozinho e foi
  o que respondeu nos testes reais.
- **Wayback CDX dá ReadTimeout na primeira tentativa** sob carga. Três tentativas
  com backoff resolveram.
- **"Todas as personas iguais" é ambíguo, e o script original tratava como
  conclusivo.** Ou existe cloaker filtrando por IP, ou não existe cloaker
  nenhum — um site comum também serve a mesma página pra todo mundo. O
  desempate é o conteúdo e o comportamento com `facebookexternalhit`. Sem essa
  distinção, a ferramenta manda comprar proxy para um alvo sem cloaker.
- **`curl_cffi` 0.16 removeu alvos de impersonate** (`safari17_0_ios`,
  `chrome124_android`). As escadas de fallback são validadas em teste para não
  gastarem round-trip com alvo inexistente.
- **Eventos de progresso precisam de uma via só.** Os estágios entram na fila
  por `call_soon_threadsafe` (o probe roda em outra thread); se o resultado
  final entrasse direto com `await fila.put`, ele ultrapassava eventos ainda
  agendados e o `None` encerrava o stream antes deles — eventos sumiam da tela.
- **Chromium headed, não headless.** Você precisa poder logar e resolver
  checkpoint, e headless tem marcas que o Meta detecta. O binário headless
  nem é necessário.
- **O projeto mora em `~/FunnelRecon`, fora de `~/Documents`, e tem que
  continuar assim.** Duas barreiras do macOS, ambas invisíveis, empilhadas:
  (a) **TCC** — o sistema proíbe um app de ler `~/Documents` sem consentimento
  explícito. O `.app` enxergava a pasta mas levava `Operation not permitted` em
  cada arquivo e morria com `No module named funnel_recon`; pelo terminal
  sempre funcionou, porque o Terminal já tem a permissão, o que fez o sintoma
  parecer aleatório. (b) **iCloud** — `~/Documents` sincroniza, e o ambiente
  Python tem ~2.300 arquivos que o iCloud descarregava e re-materializava sob
  demanda, deixando o app lento sem sinal na tela. Ambiente, banco, log e
  perfil do navegador ficam em `~/Library/Application Support/FunnelRecon/`
  (o `.venv` na pasta do projeto é só um link pra lá). SQLite em pasta
  sincronizada também corre risco de corrupção. Não mova de volta para
  Documents, Desktop nem Downloads.
- **O `.app` precisa ser assinado, nem que seja ad-hoc.** Sem assinatura o
  Gatekeeper faz uma verificação lenta a cada lançamento pelo Finder, sem
  nenhum feedback visual. `xattr -cr` antes, porque metadados do Finder
  impedem a assinatura. Se você mexer no launcher, assine de novo:
  `xattr -cr "Funnel Recon.app" && codesign --force --deep -s - "Funnel Recon.app"`
- **A Biblioteca abre em `active_status=active`.** Sem forçar `all` na URL, o
  coletor só via a campanha que está no ar — e o anúncio **encerrado** é o mais
  valioso: ninguém volta pra arrumar o filtro de campanha morta, então é nele
  que o cloaker vaza a money page. `with_all_statuses()` reescreve só esse
  parâmetro e preserva o resto da busca. O status é **tri-estado** (`True` /
  `False` / `None`): "não sei" não pode virar "encerrado", senão todo export
  antigo fura a fila de alvos do probe.
- **Página grande não termina: ela é cortada.** Numa página com dezenas de
  milhares de anúncios ativos, o critério "parou de aparecer anúncio novo"
  nunca dispara. A coleta ia até o limite de 400 rolagens (~11min) com o
  Chromium segurando um DOM que só cresce, até a rolagem estourar o timeout do
  Playwright — e a exceção levava junto tudo que já tinha sido coletado. Agora
  são três freios (`MAX_ADS=2000`, `MAX_SECONDS=300`, rolagem que falha sem
  perder o que já veio) e a coleta se declara **parcial**. Coleta parcial
  **desliga a marcação de OUTLIER**: a Biblioteca entrega os mais recentes
  primeiro, então "raro nesta fatia" não é "raro na operação", e marcar
  inventaria um achado. Para página gigante, filtre a busca na Biblioteca —
  não aumente o teto.
- **pHash, e os limiares foram medidos, não chutados.** Recompressão JPEG
  (até q25), resize 1080→320, WEBP e blur leve dão distância **0**; marca
  d'água e crop de 3% dão **8**; criativos genuinamente diferentes começam em
  **22**. Daí `SAME_MAX=10` e `DIFF_MIN=18`, com a faixa 11–17 declarada
  ambígua em vez de chutada. `tests/test_creative.py` refaz a medição a cada
  execução, então mudança no Pillow ou na DCT quebra o teste em vez de
  descalibrar em silêncio.
- **A URL de asset do Meta é assinada e expira.** Por isso o pHash é tirado na
  hora da coleta e gravado em `ad.creative_phash`. Guardar só a URL não serve:
  quando você voltasse para comparar, ela já teria morrido — e sem o hash de
  antes não existe detecção de bait-and-switch.
- **Anúncio de vídeo é comparado pela thumbnail.** Baixar e decodificar o vídeo
  exigiria ffmpeg e ordens de grandeza mais banda. O limite é real: troca de
  conteúdo no meio do vídeo passa batido.
- **O feed é oportunista, e "não vi" não é "não tem".** Não dá para invocar o
  anúncio de um anunciante — você vê o que o Meta decide te mostrar, e o que
  ele te mostra foi escolhido para o SEU perfil. Por isso `render_feed` nunca
  junta "nada encontrado" com "nada observado": são conclusões opostas na
  mesma tela. Para o alvo aparecer, interaja com o nicho dele antes.
- **`funnel_recon feed` é comando separado, não estágio da cascata.** Ele rola
  o seu feed pessoal com a sua conta. Colar um link da Biblioteca não é
  consentimento para isso.
- **As duas trilhas são separáveis porque custam coisas diferentes.** Destino
  gasta requisição contra o servidor do alvo e **expõe o seu IP residencial a
  ele**; criativo gasta download de imagem do CDN do Meta. Quem quer só uma não
  tem por que pagar o custo da outra — daí os modos. No modo "só os criativos",
  `_decide` tem um ramo próprio: sem ter sondado nada, o app não pode concluir
  nada sobre o destino, e sem esse ramo ele diria "caminhos automáticos
  esgotados, compre proxy" para quem nunca pediu o destino.
- **Criativo trocado tem veredito próprio (`criativo`), não vira `money`.** Um
  criativo trocado não diz para onde o clique vai: são perguntas diferentes. No
  modo "tudo" o achado de criativo não sequestra o veredito de destino, mas
  entra no passo seguinte — senão o cartão dele fica abaixo na página e passa
  despercebido justamente quando importa.
- **O valor está no CAMINHO, e a tela escondia isso.** Caso real: 1.128
  anúncios em `massagem.sensualdesireart.site/quiz` e 65 em `/sulamita`. A tela
  só mostrava o host, o usuário copiou o domínio, abriu a raiz e levou
  `Cannot GET /` — o 404 padrão do Express. O caminho estava coletado desde o
  primeiro dia. Agora `path_histogram` mostra cada caminho abaixo do domínio,
  com botão de copiar a URL completa. Caminho com menos da metade do volume do
  principal é marcado **VARIANTE**; volumes parecidos são funis simultâneos —
  a mesma leitura que o histograma de domínios faz.
- **Enumeração de subdomínio precisa subir para o apex.** O alvo que chega ao
  OSINT já costuma ser subdomínio (`massagem.alvo.site`). Consultar o
  Certificate Transparency com o host como veio pede `%.massagem.alvo.site` e
  devolve ele mesmo — na primeira análise real, o `app.` e o `track.` da mesma
  operação existiam e ficaram invisíveis. `apex_domain()` resolve o registrável
  (com lista curta de sufixos de dois rótulos, não a PSL inteira) e o crt.sh
  passa a listar os **irmãos**. Em `cloakby.com` isso revelou `go.`, `link.`,
  `r.` e `app.` — a infraestrutura do serviço de cloaking.
- **Plataforma de cloaking se identifica pelo domínio.** `track.cloakby.com`
  apareceu nos dados reais: é o adversário aparecendo pelo nome, não inferência
  de comportamento. `CLOAKER_BRANDS` só recebe marca confirmada em dado real; o
  resto vira suspeita pelo nome, reportada como suspeita. Isso muda o próximo
  passo — cloaker de prateleira filtra por IP/ASN antes de olhar cabeçalho.
- **Caminho arquivado só serve depois de filtrado.** O índice do Wayback guarda
  URL malformada raspada de dentro de página. Medido em `iana.org`: sem filtro
  saem 1.153 "caminhos" e as 12 primeiras linhas são todas lixo (`/&gt`,
  `/%0A`, entidade HTML virando rota); com filtro sobram 65, todos rota real.
  Domínio de funil recém-criado costuma ter **0 snapshots** — o que já é sinal.
- **Cloaker moderno não monta white page — ele despeja no site real de outra
  pessoa.** Medido nos dados reais: `achadaspremium.shop/l/…` mandou todas as
  personas humanas para `cwc.edu` (Central Wyoming College) e
  `sensualdesireart.site/quiz` mandou todas para um site de tarô. É a página de
  recusa mais barata que existe — SSL válido, conteúdo real, histórico real —
  e quem revisa o anúncio não tem o que denunciar. `bounced_offsite:` marca
  isso, e o veredito passa a ser "você foi recusado", não "travado": saber
  **para onde** o cloaker despeja o recusado é mais informativo que saber que
  as páginas batem entre si.
- **Dois falsos positivos faziam o app anunciar money page sobre uma
  faculdade.** (1) `telegram_bot` era `\b\w{3,32}bot\b`, que casa com
  "chatbot", "robot" e "Abbot" — qualquer página institucional virava suspeita
  de funil. Agora exige contexto (`@` ou `t.me/`). (2) O veredito aceitava
  **qualquer** valor capturado como prova, e `meta_pixel:` entra nessa lista —
  pixel do Facebook existe em toda loja do planeta. Agora só valor de funil
  (`telegram:`, `bot_handle:`, `whatsapp:`) decide money page. O ruído estava
  escondendo um achado real: `t.me/universitygirlsclubbot`, servido justamente
  para `facebookexternalhit` e `googlebot`, que ficaram no domínio enquanto as
  personas humanas eram despejadas.
- **Onde o cloaker decide muda o que é possível: borda vs servidor.**
  `funnel_recon origin <domínio>` resolve os subdomínios (do crt.sh) e
  classifica cada IP. Se o apex está atrás de Cloudflare, o cloaking pode estar
  na **borda** — e o servidor de origem atrás do CDN às vezes serve a money
  page sem proteção. Origem vaza por subdomínio mal-configurado (`mail.`,
  `cpanel.`, `ftp.`, `www.`) que aponta para fora do CDN. Se o apex resolve
  direto para um IP comum (Hostinger/LiteSpeed, como todo o núcleo desta
  operação), a decisão é no **servidor final** e não há borda para contornar —
  só proxy no país-alvo. O comando é **diagnóstico**: aponta o IP candidato e
  imprime o `curl --resolve` para o bypass, mas **não executa o bypass ativo**
  — esse passo é manual, do operador, no ambiente dele.
- **CDN atrás de CDN é o teste que mata o falso positivo.** Um "candidato a
  origem" pode ser só outra borda: o `thekingmanuscript` tinha Cloudflare no
  apex e **BunnyCDN** no `www` (cert `*.b-cdn.net`), origem real nunca exposta.
  `cdn_from_cert_cn()` traduz o CN que o `curl -v` mostra — `*.b-cdn.net`,
  `*.cloudfront.net`, `*.fastly.net`, `*.sucuri.net` etc. significam "ainda é
  CDN, a caça continua". Só um CN com o domínio real prova que é o servidor.
- **Contra filtro de IP não se passa — se contorna.** Nenhuma linha de código
  muda de qual IP o pacote sai, então persona/header não vencem cloaker de IP.
  Mas o operador quase sempre põe o cloaker no endereço que o **anúncio**
  aponta e esquece o resto do domínio. Caso real: `massagem.sensualdesireart.
  site/quiz` despejava toda persona num site de tarô, enquanto o apex
  `sensualdesireart.site` servia a VSL **aberta** — WordPress com `wp-json`
  exposto, que entregou o inventário completo (`/main/`, `/main-es/`) sem
  adivinhar path. O checkout estava no HTML: `checkout-ds24.com/product/687041`
  (inglês) e `payment.loversecretguide.site` (espanhol). `sidedoor.py` tenta
  apex → inventário do CMS → sitemap, nessa ordem de custo, e só quando o probe
  não chegou. **Não faz força bruta de diretório**: seria barulho, queimaria o
  IP residencial, e é adivinhação quando o próprio site publica o índice. Se as
  três portas falharem, a resposta honesta continua sendo proxy no país-alvo.
- **O checkout é o fim da linha.** `checkout:` e `vsl_player:` viraram sinais
  de valor: o ID do produto (`687041` no Digistore24) identifica a oferta mesmo
  quando o domínio da VSL for trocado amanhã. É o pivô mais durável que existe.
- **urlscan.io já entregava a oferta na busca, sem chave.** O endpoint
  `/result/` passou a exigir API-Key (403), mas a **busca** devolve IP, ASN,
  país, idade do domínio, título e o link do **screenshot** — que abre sem
  chave. Foi um screenshot público (escaneado da França) que mostrou a VSL real
  antes mesmo de bater no site.
- **`content.rendered` da REST fura gate de referer.** Páginas de funil
  costumam checar o `Referer` e devolver 400 no fetch direto. Mas o mesmo HTML
  sai limpo pelo `content` da REST do WordPress (`wp-json/wp/v2/pages?_fields=
  link,content`). Foi assim que o funil de upsells inteiro (`up1/up2/up3`,
  variantes Hotmart e França) apareceu num caso real — a porta lateral usa o
  HTML embutido quando ele vem, e só busca a URL quando não vem.
- **Uma operação cruza domínios pelo mesmo vídeo.** O GUID do VTurb
  (`vsl_video:`) é a impressão digital que liga tudo: `sensualdesireart.site`
  (produto 687041) e `shulamitemethod.com` (produtos 693074, 705595, afiliado
  REGMarketing, campanhas sul/slmfr) rodam o **mesmo** vídeo `81d625dd…` = a
  mesma oferta "Lover's Trick". Mesmo vídeo em domínios diferentes = mesmo dono.
- **Página estática deixada no ar pode ser isca.** Confirmado por um operador:
  as páginas de VSL antiga que ficam acessíveis no apex (`/main/`, `/main-es/`)
  às vezes são deixadas **de propósito**, para concorrentes clonarem a versão
  velha enquanto a atual roda atrás do cloaker. A porta lateral acha a página;
  saber se é a VSL **atual** exige comparar o ID do vídeo (VTurb/converteai)
  com o que quem tem acesso realmente vê — `funnel_recon page`.
- **`funnel_recon page` transforma acesso alheio em dado.** A VSL servida ao
  tráfego aprovado vive atrás do filtro de IP; de um IP errado ninguém a
  alcança. Mas quem tem acesso legítimo salva a página (Cmd+S) e passa o
  arquivo: o comando extrai vídeo, checkout, produto e pixel, e compara duas
  radiografias — "MESMA VSL", "MESMA OFERTA VÍDEO NOVO" ou "OFERTA DIFERENTE".
  É o "clique humano no país-alvo" que o brief previu, feito por um conhecido
  em vez de um freelancer. `vsl_video:` (o GUID do converteai) é o que
  diferencia uma VSL da outra; `product_id` do checkout é o que identifica a
  oferta através de trocas de domínio e vídeo.
- **Cloakers de prateleira nomeados em campo:** CloakBy (visto em dados reais),
  CloakUp e The White Rabbit (citados por operador como topo de linha). Todos
  filtram por IP/ASN antes de qualquer cabeçalho — contra eles a saída é porta
  lateral ou proxy no país-alvo, nunca ajuste de persona.
- **Par de nameservers é assinatura de conta.** Cloudflare atribui o par por
  conta, não por domínio — dois domínios com o mesmo par saem do mesmo operador.
  É o pivô mais barato para achar o resto da operação.
