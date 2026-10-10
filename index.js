import { searchDuffelOffers, getDuffelOffer } from './duffel.js';
import { FlightProviderError } from './errors.js';
export { FlightProviderError } from './errors.js';

export function flightProviderStatus() {
  const provider = String(process.env.FLIGHT_PROVIDER || 'none').trim().toLowerCase();
  if (provider === 'none' || !provider) {
    return { provider: 'none', configured: false, status: 'not_configured', message: 'A busca automática ainda não está configurada. Nenhum voo ou preço fictício será exibido.' };
  }
  if (provider === 'duffel') {
    const token = String(process.env.DUFFEL_ACCESS_TOKEN || '').trim();
    if (!token || /^(COLE_AQUI|SUBSTITUA|YOUR_|CHANGE_ME)/i.test(token)) return { provider: 'duffel', configured: false, status: 'missing_credentials', message: 'Configure DUFFEL_ACCESS_TOKEN com o token live real no ambiente do servidor para ativar a busca automática.' };
    if (token.startsWith('duffel_test_')) return { provider: 'duffel', configured: false, status: 'test_token', message: 'O token Duffel de teste não pode ser usado para mostrar preços reais. Configure um token live aprovado.' };
    if (!token.startsWith('duffel_live_')) return { provider: 'duffel', configured: false, status: 'invalid_token_format', message: 'O token não parece ser uma credencial live Duffel válida. Confira o token no painel do fornecedor.' };
    return { provider: 'duffel', configured: true, status: 'ready', message: 'Busca automática conectada ao Duffel. Ofertas e preços dependem da cobertura da rota.' };
  }
  return { provider, configured: false, status: 'unsupported_provider', message: 'O provedor configurado não é suportado por esta versão.' };
}

export async function searchProviderFlights(params) {
  const status = flightProviderStatus();
  if (!status.configured) return { ...status, offers: [] };
  if (status.provider === 'duffel') {
    const offers = await searchDuffelOffers(params);
    return { ...status, status: offers.length ? 'results' : 'no_results', message: offers.length ? status.message : 'A fonte de dados não retornou ofertas para esta rota, data e quantidade de passageiros.', offers };
  }
  throw new FlightProviderError('O provedor de voos configurado não é suportado.', 503, 'UNSUPPORTED_PROVIDER');
}

export async function getProviderOffer(offerId) {
  const status = flightProviderStatus();
  if (!status.configured || status.provider !== 'duffel') {
    throw new FlightProviderError('A integração de voos ao vivo não está configurada.', 503, 'PROVIDER_NOT_CONFIGURED');
  }
  return getDuffelOffer(offerId);
}
