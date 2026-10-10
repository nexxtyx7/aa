import { searchDuffelOffers, getDuffelOffer } from './duffel.js';
import { searchIgnavOffers, getIgnavOffer } from './ignav.js';
import { FlightProviderError } from './errors.js';
export { FlightProviderError } from './errors.js';

export function flightProviderStatus() {
  const provider = String(process.env.FLIGHT_PROVIDER || 'none').trim().toLowerCase();
  if (provider === 'none' || !provider) {
    return { provider: 'none', configured: false, status: 'not_configured', message: 'A busca automática ainda não está configurada. Nenhum voo ou preço fictício será exibido.' };
  }
  if (provider === 'ignav') {
    const key = String(process.env.IGNAV_API_KEY || '').trim();
    if (!key || /^(COLE_AQUI|SUBSTITUA|YOUR_|CHANGE_ME)/i.test(key)) return { provider: 'ignav', configured: false, status: 'missing_credentials', message: 'Configure IGNAV_API_KEY no ambiente do servidor para ativar a busca automática.' };
    return { provider: 'ignav', configured: true, status: 'ready', message: 'Busca automática conectada à Ignav. Preços e disponibilidade precisam ser confirmados antes da emissão.' };
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
  if (status.provider === 'ignav') {
    const offers = await searchIgnavOffers(params);
    return { ...status, status: offers.length ? 'results' : 'no_results', message: offers.length ? status.message : 'A Ignav não retornou ofertas verificadas para esta rota e data.', offers };
  }
  throw new FlightProviderError('O provedor de voos configurado não é suportado.', 503, 'UNSUPPORTED_PROVIDER');
}

export async function getProviderOffer(offerId) {
  const status = flightProviderStatus();
  if (!status.configured) throw new FlightProviderError('A integração de voos ao vivo não está configurada.', 503, 'PROVIDER_NOT_CONFIGURED');
  if (status.provider === 'duffel') return getDuffelOffer(offerId);
  if (status.provider === 'ignav') return getIgnavOffer(String(offerId || '').replace(/^ignav:/, ''));
  throw new FlightProviderError('O provedor de voos configurado não é suportado.', 503, 'UNSUPPORTED_PROVIDER');
}
