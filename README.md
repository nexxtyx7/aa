# André Aéreas — site + painel + busca automática de voos

Projeto Node.js 22 + Express + SQLite. O site público pesquisa ofertas automaticamente através de um adaptador de provedor; o painel administrativo continua disponível para clientes, cotações, compras, milhas e, opcionalmente, voos verificados cadastrados manualmente.

## Integração de voos e cobertura

O adaptador desta versão usa a **Duffel Flights API** em modo live. A Duffel publica cobertura para as três companhias solicitadas:

- **LATAM:** aparece na lista de companhias com conexão direta.
- **Azul:** listada através da Travelport.
- **GOL:** listada através da Travelport.

Isso indica que as companhias constam no catálogo público da Duffel, mas **não garante que toda rota, data, tarifa ou voo esteja disponível em cada pesquisa**. A cobertura efetiva também depende das permissões comerciais e do conteúdo liberado para a conta. A disponibilidade real depende da ativação da conta, do conteúdo autorizado para a conta e das respostas do fornecedor. O acesso live não deve ser considerado gratuito: podem existir critérios de aprovação, taxas ou condições comerciais. Não há garantia de uma API gratuita que forneça tarifas reais e completas das três companhias. O token de teste `duffel_test_...` serve apenas para desenvolvimento e não fornece preços reais; este projeto recusa esse token na busca pública para não exibir preços fictícios.

Fontes oficiais consultadas:
- Duffel — lista de companhias: https://duffel.com/flights/airlines
- Duffel — LATAM: https://duffel.com/blog/latam-joins-duffel
- Duffel — Azul: https://duffel.com/flights/airlines/azul
- Duffel — GOL: https://duffel.com/flights/airlines/gol-intelligent-airlines
- Duffel — modo de teste não tem preços reais: https://help.duffel.com/hc/en-gb/articles/4410085835282-Are-the-flight-prices-in-test-mode-sandbox-real

## Variáveis de ambiente

Configure-as no painel do Render em **Environment**. Não coloque tokens no HTML, no GitHub ou em qualquer arquivo público.

### Obrigatórias para produção

- `NODE_ENV=production` — ativa configurações de produção.
- `ADMIN_PASSWORD` — senha forte do painel administrativo.
- `SESSION_SECRET` — segredo aleatório longo usado para assinar sessões.

### Obrigatórias para busca automática real

- `FLIGHT_PROVIDER=duffel`
- `DUFFEL_ACCESS_TOKEN` — token **live** gerado após ativação/aprovação da conta Duffel. Não use `duffel_test_...` para exibir preços.

### Opcionais para busca e atendimento

- `DUFFEL_API_BASE_URL=https://api.duffel.com` — URL base da API.
- `FLIGHT_CURRENCY=BRL` — moeda solicitada para as ofertas.
- `FLIGHT_MAX_RESULTS=30` — limite de ofertas mostradas (máximo interno: 50).
- `WHATSAPP_PHONE=553591793515` — número comercial em formato internacional, só dígitos, sem `+`.
- `DATABASE_PATH=/var/data/andre-aereas.db` — caminho do banco SQLite. No Render, configure-o para um diretório de Persistent Disk montado; sem isso, o banco local pode ser perdido em um novo deploy/restart.

### Opcionais para recuperação de senha por e-mail

- `APP_BASE_URL=https://SEU-SERVICO.onrender.com`
- `SMTP_HOST`
- `SMTP_PORT=587`
- `SMTP_SECURE=false` (use `true` se o provedor exigir TLS implícito)
- `SMTP_USER`
- `SMTP_PASS`
- `MAIL_FROM`

`PORT` é fornecida pelo Render automaticamente; localmente, o padrão é `3000`. `EXPOSE_DEV_RESET_TOKEN` deve permanecer `false` em produção.

## Deploy no Render (Node.js 22)

- Runtime: Node.
- Node version: 22.x (o `package.json` também declara Node 22).
- Build command: `npm install`.
- Start command: `npm start`.
- Configure as variáveis de ambiente acima no Render.
- Para preservar clientes, cotações, compras e milhas entre deploys, crie um Persistent Disk e defina `DATABASE_PATH` para um arquivo dentro do diretório de montagem.
- Nunca publique `.env` nem o token da Duffel.

## Execução local

1. Instale Node.js 22.
2. Execute `npm install`.
3. Copie `.env.example` para `.env` e preencha as variáveis necessárias.
4. Execute `npm start`.
5. Site: `http://localhost:3000`; painel: `http://localhost:3000/admin`; conta: `http://localhost:3000/conta`.
6. Verifique sintaxe com `npm run check`.

## O que mudou

- Busca por origem/destino IATA, ida, volta, passageiros e classe. A lista inicial de aeroportos populares já vem incluída e não exige cadastro manual no painel.
- Módulo de provedor separado em `services/flightProviders/`, com adaptador Duffel e ponto de extensão para trocar de provedor.
- Validação da pesquisa e tratamento de timeout, limite de chamadas, falhas do provedor e ausência de resultados.
- Somente ofertas com `live_mode=true` são exibidas; token de teste é recusado para a busca pública.
- Os cartões indicam companhia, horários, duração, escalas, preço total retornado e fonte. A tela de detalhes mostra os trechos de ida e volta.
- Ao pedir cotação de uma oferta externa, o servidor consulta a oferta novamente e valida rota, datas e passageiros antes de registrar a cotação e abrir o WhatsApp comercial.
- A busca de voos é pública, mas para registrar uma cotação e abrir o WhatsApp é necessário entrar na conta do cliente. A solicitação fica vinculada ao usuário autenticado.
- O painel de voos manuais continua disponível para casos verificados, mas não é necessário cadastrar cada voo para usar a busca automática.
- Banco SQLite criado automaticamente se o diretório de destino não existir.

## Limitações importantes

- Esta integração de código não ativa uma conta de fornecedor nem cria credenciais. Antes de mostrar ofertas reais, é necessário obter um token live válido e confirmar no painel do fornecedor as permissões e condições comerciais para LATAM, Azul e GOL.
- A cobertura de catálogo não é garantia de resultados para todas as rotas; a aplicação informa quando não há ofertas.
- A cotação pelo WhatsApp não emite passagem nem garante o preço: a equipe deve confirmar preço e disponibilidade antes de vender.
- O SQLite só persiste no Render se o serviço tiver Persistent Disk corretamente configurado.
- A recuperação de senha por e-mail só funciona depois de configurar SMTP.
- Não há gateway de pagamento integrado. O painel preserva gestão de compras confirmadas e milhas.


## Nota sobre as credenciais

Este ZIP não contém um token real da Duffel. Até que `DUFFEL_ACCESS_TOKEN` seja configurado com credenciais live válidas e a conta tenha permissão para consultar as companhias/rotas necessárias, a aplicação informa que a busca automática não está pronta e não inventa voos ou preços. O status pode ser consultado em `/api/flight-provider-status`.
