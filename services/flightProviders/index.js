
import { searchIgnavOffers, getIgnavOffer } from './ignav.js';
import { FlightProviderError } from './errors.js';

export { FlightProviderError } from './errors.js';

export function flightProviderStatus() {
  const provider = String(
    process.env.FLIGHT_PROVIDER || 'none'
  ).trim().toLowerCase();

  if (provider === 'none' || !provider) {
    return {
      provider: 'none',
      configured: false,
      status: 'not_configured',
      message: 'A busca automática ainda não está configurada.'
    };
  }

  if (provider === 'ignav') {
    const key = String(process.env.IGNAV_API_KEY || '').trim();

    if (!key || /^(COLE_AQUI|SUBSTITUA|YOUR_|CHANGE_ME)/i.test(key)) {
      return {
        provider: 'ignav',
        configured: false,
        status: 'missing_credentials',
        message: 'Configure IGNAV_API_KEY no ambiente do servidor.'
      };
    }

    return {
      provider: 'ignav',
      configured: true,
      status: 'ready',
      message: 'Busca conectada à Ignav. Preços e disponibilidade devem ser confirmados antes da emissão.'
    };
  }

  return {
    provider,
    configured: false,
    status: 'unsupported_provider',
    message: 'O provedor configurado não é suportado.'
  };
}

export async function searchProviderFlights(params) {
  const status = flightProviderStatus();

  if (!status.configured) {
    return { ...status, offers: [] };
  }

  if (status.provider === 'ignav') {
    const offers = await searchIgnavOffers(params);

    return {
      ...status,
      status: offers.length ? 'results' : 'no_results',
      message: offers.length
        ? status.message
        : 'A Ignav não retornou ofertas verificadas para esta rota e data.',
      offers
    };
  }

  throw new FlightProviderError(
    'O provedor de voos configurado não é suportado.',
    503,
    'UNSUPPORTED_PROVIDER'
  );
}

export async function getProviderOffer(offerId) {
  const status = flightProviderStatus();

  if (!status.configured) {
    throw new FlightProviderError(
      'A integração de voos ao vivo não está configurada.',
      503,
      'PROVIDER_NOT_CONFIGURED'
    );
  }

  if (status.provider === 'ignav') {
    return getIgnavOffer(
      String(offerId || '').replace(/^ignav:/, '')
    );
  }

  throw new FlightProviderError(
    'O provedor de voos configurado não é suportado.',
    503,
    'UNSUPPORTED_PROVIDER'
  );
}
