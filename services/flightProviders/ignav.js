
import { FlightProviderError } from './errors.js';

const API_BASE = 'https://ignav.com/api';

function apiKey() {
  return String(process.env.IGNAV_API_KEY || '').trim();
}

async function request(endpoint, body) {
  const key = apiKey();

  if (!key) {
    throw new FlightProviderError(
      'Configure IGNAV_API_KEY no ambiente do servidor.',
      503,
      'MISSING_IGNAV_KEY'
    );
  }

  let response;

  try {
    response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      signal: AbortSignal.timeout(18000),
      headers: {
        'X-Api-Key': key,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify(body)
    });
  } catch (error) {
    const timedOut = error?.name === 'TimeoutError';

    throw new FlightProviderError(
      timedOut
        ? 'A pesquisa demorou demais. Tente novamente.'
        : 'Não foi possível conectar à fonte de voos.',
      502,
      timedOut ? 'IGNAV_TIMEOUT' : 'IGNAV_UNREACHABLE'
    );
  }

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const status =
      response.status === 429 ? 503 :
      response.status >= 500 ? 502 :
      response.status === 401 || response.status === 403 ? 503 : 422;

    console.error('[flight-provider] Ignav request failed', {
      status: response.status
    });

    throw new FlightProviderError(
      response.status === 401 || response.status === 403
        ? 'A API Ignav recusou a credencial. Confira a chave no Render.'
        : response.status === 429
          ? 'Limite temporário da API atingido. Tente novamente mais tarde.'
          : 'A API não aceitou a pesquisa. Confira aeroportos, datas e passageiros.',
      status,
      'IGNAV_REQUEST_FAILED'
    );
  }

  return payload;
}

function normalizeSegment(segment) {
  const airlineCode = segment.marketing_carrier_code || '';
  const flightNumber = segment.flight_number || '';

  return {
    airline_name:
      segment.operating_carrier_name ||
      'Companhia não informada pela fonte',
    airline_code: airlineCode,
    operating_airline_name: segment.operating_carrier_name || '',
    flight_code: `${airlineCode} ${flightNumber}`.trim(),
    origin_city: segment.departure_airport || '',
    origin_code: segment.departure_airport || '',
    destination_city: segment.arrival_airport || '',
    destination_code: segment.arrival_airport || '',
    departure_time: String(segment.departure_time_local || '').slice(11, 16) || '—',
    arrival_time: String(segment.arrival_time_local || '').slice(11, 16) || '—',
    departure_at: segment.departure_time_local || null,
    arrival_at: segment.arrival_time_local || null,
    duration_minutes: Number(segment.duration_minutes || 0),
    aircraft: segment.aircraft || null
  };
}

export function normalizeIgnavOffer(offer) {
  const outbound = offer?.outbound;
  const inbound = offer?.inbound;
  const outboundSegments = (outbound?.segments || []).map(normalizeSegment);
  const returnSegments = (inbound?.segments || []).map(normalizeSegment);

  const first = outboundSegments[0];
  const last = outboundSegments.at(-1);
  const returnFirst = returnSegments[0];
  const returnLast = returnSegments.at(-1);

  const amount = Number(offer?.price?.amount);
  const currency = String(offer?.price?.currency || '').toUpperCase();
  const priceStatus = String(offer?.price?.status || '').toLowerCase();

  // Não apresentar preços não verificados como cotações confirmadas.
  if (
    !first ||
    !last ||
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !currency ||
    priceStatus !== 'verified'
  ) {
    return null;
  }

  return {
    id: `ignav:${offer.ignav_id}`,
    provider_offer_id: offer.ignav_id,
    source_type: 'provider',
    source: 'Ignav',
    airline_name: outbound.carrier || first.airline_name,
    flight_code: first.flight_code || 'Voo informado pela fonte',
    origin_city: first.origin_city,
    origin_code: first.origin_code,
    destination_city: last.destination_city,
    destination_code: last.destination_code,
    departure_date: String(first.departure_at || '').slice(0, 10),
    return_date: returnFirst
      ? String(returnFirst.departure_at || '').slice(0, 10)
      : null,
    departure_time: first.departure_time,
    arrival_time: last.arrival_time,
    duration_minutes: Number(outbound.duration_minutes || 0),
    stops: Math.max(0, outboundSegments.length - 1),
    cabin: offer.cabin_class || 'economy',
    price: amount,
    currency,
    price_status: priceStatus,
    passenger_count: null,
    requires_self_transfer: offer.requires_self_transfer === true,
    return_info: returnFirst && returnLast
      ? {
          airline_name: inbound.carrier || returnFirst.airline_name,
          flight_code: returnFirst.flight_code,
          origin_city: returnFirst.origin_city,
          origin_code: returnFirst.origin_code,
          destination_city: returnLast.destination_city,
          destination_code: returnLast.destination_code,
          departure_time: returnFirst.departure_time,
          arrival_time: returnLast.arrival_time,
          duration_minutes: Number(inbound.duration_minutes || 0),
          stops: Math.max(0, returnSegments.length - 1)
        }
      : null,
    outbound_segments: outboundSegments,
    return_segments: returnSegments,
    observed_at: offer.observed_at || null,
    cache_hit: offer.cache_hit === true,
    live_mode: true
  };
}

export async function searchIgnavOffers({
  origin,
  destination,
  departureDate,
  returnDate,
  passengers = 1,
  cabin = 'economy'
}) {
  const adults = Math.min(9, Math.max(1, Number(passengers) || 1));
  const cabinMap = {
    economy: 'economy',
    premium_economy: 'premium_economy',
    business: 'business',
    first: 'first'
  };

  const body = {
    origin: String(origin || '').trim().toUpperCase(),
    destination: String(destination || '').trim().toUpperCase(),
    departure_date: departureDate,
    adults,
    cabin_class: cabinMap[cabin] || 'economy',
    market: String(process.env.FLIGHT_MARKET || 'BR').toUpperCase()
  };

  if (!/^[A-Z]{3}$/.test(body.origin) ||
      !/^[A-Z]{3}$/.test(body.destination)) {
    throw new FlightProviderError(
      'Informe aeroportos válidos usando códigos IATA de três letras.',
      400,
      'INVALID_AIRPORT'
    );
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(departureDate || ''))) {
    throw new FlightProviderError(
      'Informe uma data de ida válida.',
      400,
      'INVALID_DEPARTURE_DATE'
    );
  }

  if (returnDate &&
      (!/^\d{4}-\d{2}-\d{2}$/.test(String(returnDate)) ||
       returnDate < departureDate)) {
    throw new FlightProviderError(
      'A data de volta deve ser igual ou posterior à data de ida.',
      400,
      'INVALID_RETURN_DATE'
    );
  }

  const endpoint = returnDate
    ? '/fares/round-trip'
    : '/fares/one-way';

  if (returnDate) body.return_date = returnDate;

  const data = await request(endpoint, body);
  const maxResults = Math.min(
    50,
    Math.max(1, Number(process.env.FLIGHT_MAX_RESULTS || 30))
  );

  return (Array.isArray(data?.itineraries) ? data.itineraries : [])
    .map(offer => ({
      ...offer,
      observed_at: data.observed_at || null,
      cache_hit: data.cache_hit === true
    }))
    .map(normalizeIgnavOffer)
    .filter(Boolean)
    .sort((a, b) => a.price - b.price)
    .slice(0, maxResults);
}

export async function getIgnavOffer(offerId) {
  const id = String(offerId || '').trim();

  if (!/^[A-Za-z0-9_-]{8,128}$/.test(id)) {
    throw new FlightProviderError(
      'A oferta selecionada não é válida. Faça uma nova pesquisa.',
      400,
      'INVALID_IGNAV_OFFER_ID'
    );
  }

  const data = await request('/fares/booking-links', {
    ignav_id: id
  });

  const offer = normalizeIgnavOffer({
    ...data?.itinerary,
    ignav_id: id
  });

  if (!offer) {
    throw new FlightProviderError(
      'Não foi possível confirmar o preço desta oferta. Faça uma nova pesquisa.',
      409,
      'IGNAV_OFFER_UNVERIFIED'
    );
  }

  return {
    ...offer,
    booking_options: Array.isArray(data?.booking_options)
      ? data.booking_options
      : []
  };
}
