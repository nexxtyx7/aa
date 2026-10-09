# André Aéreas — site + sistema inicial de atendimento

Este pacote continua o site visual existente e adiciona uma base de backend persistente. Não inclui dados de voos de exemplo e não inclui credenciais reais.

## Tecnologias
- Node.js 20+
- Express 5, Helmet, Morgan
- SQLite via `better-sqlite3` (arquivo persistente em `data/andre-aereas.db`)
- Senhas de clientes com `scrypt`; tokens de sessão aleatórios armazenados no banco apenas como SHA-256

## Instalação local
1. Instale Node.js 20 ou superior.
2. Extraia o ZIP e abra a pasta no terminal.
3. Execute `npm install`.
4. Copie `.env.example` para `.env` e troque os valores por segredos fortes. Não publique `.env`.
5. Execute `npm start`.
6. Abra `http://localhost:3000`, a área do cliente em `/conta` e o painel em `/admin`.

O servidor lê variáveis de ambiente do processo. Para carregar `.env` localmente, use Node 20+ com `node --env-file=.env server.js` (ou ajuste o script `start` para `node --env-file=.env server.js`). Em hospedagem, configure as variáveis no painel do provedor. Não use os valores de exemplo em produção.

## O que está implementado no código
- Site público com busca conectada à API de voos cadastrados no banco; nenhum voo é pré-carregado como se fosse real.
- Painel existente para cadastro manual de aeroportos e voos. Cadastre apenas dados verificados e mantenha disponibilidade/preço atualizados.
- API de solicitação de cotação que registra a solicitação e devolve link `wa.me` preenchido; a solicitação pode ser anônima ou vinculada a uma sessão de cliente.
- Cadastro de cliente, login/logout, senha com hash scrypt, sessão persistente no servidor e endpoint de recuperação de senha.
- Área `/conta` com histórico de cotações, compras e extrato de milhas para clientes autenticados.
- APIs administrativas para visão geral, status de cotações, registro único de compra por cotação, configuração do programa de milhas, ajuste manual justificado, lista de clientes e auditoria.
- A compra confirmada só concede milhas se o programa estiver **ativo e aprovado**. A compra por cotação é única e o lançamento de milhas usa chave única para evitar duplicação.
- Página inicial de privacidade em `/privacidade`; deve ser revisada pelo responsável jurídico/operacional antes de publicação.

## Estados de cotação
`pending` (pendente), `in_progress` (em atendimento), `quote_sent` (cotação enviada), `purchase_confirmed` (compra confirmada), `cancelled` (cancelada).

## Integrações pendentes / limites conhecidos
- **API de voos:** ainda não conectada. É necessário contratar/autorizar um fornecedor, obter credenciais e implementar seu adaptador. Até lá, resultados só aparecem se o administrador inserir dados verificados manualmente.
- **Recuperação por e-mail:** o endpoint cria token de recuperação com expiração, mas o envio de e-mail não está ligado a SMTP/provedor transacional. Em desenvolvimento, o token só é retornado se `EXPOSE_DEV_RESET_TOKEN=true`; não habilite isso em produção.
- **Pagamentos/parcelamento via Pix:** não há gateway de pagamento integrado; o responsável combina as condições fora do site. Não coletar dados de cartão.
- **Milhas/resgates:** configurações e créditos por compra confirmada estão implementados. O fluxo completo de resgate/benefício ainda precisa de política aprovada e telas/API de solicitação e aprovação de resgates antes de oferecer resgates aos clientes. Valores iniciais do banco são provisórios e o programa começa desativado/não aprovado.
- **LGPD:** a página é um modelo inicial, não uma avaliação jurídica. O responsável precisa completar identidade do controlador, canal dedicado, prazos, retenção, procedimento de exclusão/exportação e revisar bases legais/avisos.
- **Produção:** publicar somente atrás de HTTPS, configurar `NODE_ENV=production`, `ADMIN_PASSWORD` forte e `SESSION_SECRET` forte; fazer backups protegidos do SQLite e testar restauração. Recomenda-se trocar o login administrativo legado por autenticação individual de funcionários antes de produção.

## Testes executados neste pacote
- `node --check server.js`.
- Verificação de sintaxe dos scripts inline de `index.html` e `conta.html`.
- Verificação de sintaxe do script inline de `admin.html`.

A instalação de dependências e um teste de integração real do servidor não foram concluídos neste ambiente; portanto, cadastro/login/API/banco não devem ser considerados testados de ponta a ponta até rodar `npm install` e seguir os testes manuais em ambiente local.


## Atualização desta versão
- O cabeçalho da página inicial agora mostra o link **Entrar / Criar conta**, que abre `/conta.html`.
- O link é responsivo para celular. Para que login/cadastro funcionem, o servidor Node.js descrito neste README precisa estar hospedado e executando; apenas publicar os arquivos estáticos no GitHub Pages não executa `server.js` nem as APIs `/api`.
