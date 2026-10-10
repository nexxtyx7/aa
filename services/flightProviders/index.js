
import { searchDuffelOffers, getDuffelOffer } from './duffel.js';
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
      message: 'A busca automática ainda não está configurada. Nenhum voo ou preço fictício será exibido.'
    };
  }

  if (provider === 'ignav') {
    const key = String(process.env.IGNAV_API_KEY || '').trim();

    if (!key) {
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
      message: 'Busca de voos conectada à Ignav. Os preços e a disponibilidade dependem dos resultados da fonte.'
    };
  }

  if (provider === 'duffel') {
    const token = String(
      process.env.DUFFEL_ACCESS_TOKEN || ''
    ).trim();

    if (
      !token ||
      /^(COLE_AQUI|SUBSTITUA|YOUR_|CHANGE_ME)/i.test(token)
    ) {
      return {
        provider: 'duffel',
        configured: false,
        status: 'missing_credentials',
        message: 'Configure DUFFEL_ACCESS_TOKEN no ambiente do servidor.'
      };
    }

    if (token.startsWith('duffel_test_')) {
      return {
        provider: 'duffel',
        configured: false,
        status: 'test_token',
        message: 'O token Duffel de teste não pode ser usado para mostrar preços reais. Configure um token live aprovado.'
      };
    }

    if (!token.startsWith('duffel_live_')) {
      return {
        provider: 'duffel',
        configured: false,
        status: 'invalid_token_format',
        message: 'Confira o formato do token Duffel no painel do fornecedor.'
      };
    }

    return {
      provider: 'duffel',
      configured: true,
      status: 'ready',
      message: 'Busca automática conectada ao Duffel.'
    };
  }

  return {
    provider,
    configured: false,
    status: 'unsupported_provider',
    message: 'O provedor configurado não é suportado por esta versão.'
  };
}

export async function searchProviderFlights(params) {
  const status = flightProviderStatus();

  if (!status.configured) {
    return { ...status, offers: [] };
  }

  let offers;

  if (status.provider === 'ignav') {
    offers = await searchIgnavOffers(params);
  } else if (status.provider === 'duffel') {
    offers = await searchDuffelOffers(params);
  } else {
    throw new FlightProviderError(
      'O provedor de voos configurado não é suportado.',
      503,
      'UNSUPPORTED_PROVIDER'
    );
  }

  return {
    ...status,
    status: offers.length ? 'results' : 'no_results',
    message: offers.length
      ? status.message
      : 'A fonte não retornou preços verificados para esta rota e data. Tente outra data.',
    offers
  };
}

export async function getProviderOffer(offerId) {
  const status = flightProviderStatus();

  if (!status.configured) {
    throw new FlightProviderError(
      'A integração de voos não está configurada.',
      503,
      'PROVIDER_NOT_CONFIGURED'
    );
  }

  const id = String(offerId || '');

  if (status.provider === 'ignav') {
    if (!id.startsWith('ignav:')) {
      throw new FlightProviderError(
        'A oferta selecionada não pertence à Ignav.',
        400,
        'INVALID_PROVIDER_OFFER'
      );
    }

    return getIgnavOffer(id.slice('ignav:'.length));
  }

  if (status.provider === 'duffel') {
    return getDuffelOffer(id);
  }

  throw new FlightProviderError(
    'O provedor de voos configurado não é suportado.',
    503,
    'UNSUPPORTED_PROVIDER'
  );
}
