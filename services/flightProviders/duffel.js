import { FlightProviderError } from './errors.js';

const API_BASE = () => String(process.env.DUFFEL_API_BASE_URL || 'https://api.duffel.com').replace(/\/$/, '');
const CURRENCY = () => String(process.env.FLIGHT_CURRENCY || 'BRL').toUpperCase();

function parseDuration(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.round(value);
  const match = String(value || '').match(/^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?$/i);
  if (!match) return 0;
  return Number(match[1] || 0) * 1440 + Number(match[2] || 0) * 60 + Number(match[3] || 0);
}

function segmentView(segment) {
  const carrier = segment.marketing_carrier || segment.operating_carrier || {};
  const operating = segment.operating_carrier || carrier;
  const flightNumber = segment.marketing_carrier_flight_number || segment.operating_carrier_flight_number || '';
  return {
    airline_name: carrier.name || operating.name || 'Companhia não informada pela fonte',
    airline_code: carrier.iata_code || operating.iata_code || '',
    operating_airline_name: operating.name || carrier.name || '',
    flight_code: `${carrier.iata_code || operating.iata_code || ''}${flightNumber ? ` ${flightNumber}` : ''}`.trim(),
    origin_city: segment.origin?.city_name || segment.origin?.name || segment.origin?.iata_code || '',
    origin_code: segment.origin?.iata_code || '',
    destination_city: segment.destination?.city_name || segment.destination?.name || segment.destination?.iata_code || '',
    destination_code: segment.destination?.iata_code || '',
    departure_time: String(segment.departing_at || '').slice(11, 16) || '—',
    arrival_time: String(segment.arriving_at || '').slice(11, 16) || '—',
    departure_at: segment.departing_at || null,
    arrival_at: segment.arriving_at || null,
    duration_minutes: parseDuration(segment.duration),
    aircraft: segment.aircraft?.name || null
  };
}

export function normalizeDuffelOffer(offer) {
  const slices = Array.isArray(offer?.slices) ? offer.slices : [];
  const outboundSegments = (slices[0]?.segments || []).map(segmentView);
  const returnSegments = (slices[1]?.segments || []).map(segmentView);
  const first = outboundSegments[0];
  const last = outboundSegments.at(-1);
  if (!first || !last) return null;
  const returnFirst = returnSegments[0];
  const returnLast = returnSegments.at(-1);
  const price = Number(offer.total_amount);
  if (!Number.isFinite(price) || price < 0) return null;
  const currency = String(offer.total_currency || CURRENCY()).toUpperCase();
  const totalDuration = parseDuration(slices[0]?.duration) || outboundSegments.reduce((sum, s) => sum + Number(s.duration_minutes || 0), 0);
  const returnDuration = returnSegments.length ? (parseDuration(slices[1]?.duration) || returnSegments.reduce((sum, s) => sum + Number(s.duration_minutes || 0), 0)) : 0;
  const passengers = Array.isArray(offer.passengers) ? offer.passengers.length : null;
  return {
    id: `duffel:${offer.id}`,
    provider_offer_id: offer.id,
    source_type: 'provider',
    source: 'Duffel',
    airline_name: first.airline_name,
    flight_code: first.flight_code || 'Voo informado pela companhia',
    origin_city: first.origin_city,
    origin_code: first.origin_code,
    destination_city: last.destination_city,
    destination_code: last.destination_code,
    departure_date: String(first.departure_at || '').slice(0, 10),
    return_date: returnFirst ? String(returnFirst.departure_at || '').slice(0, 10) : null,
    departure_time: first.departure_time,
    arrival_time: last.arrival_time,
    duration_minutes: totalDuration,
    stops: Math.max(0, outboundSegments.length - 1),
    cabin: offer.slices?.[0]?.segments?.[0]?.passengers?.[0]?.cabin_class || 'Conforme oferta',
    price,
    currency,
    passenger_count: passengers,
    return_info: returnFirst && returnLast ? {
      airline_name: returnFirst.airline_name,
      flight_code: returnFirst.flight_code,
      origin_city: returnFirst.origin_city,
      origin_code: returnFirst.origin_code,
      destination_city: returnLast.destination_city,
      destination_code: returnLast.destination_code,
      departure_time: returnFirst.departure_time,
      arrival_time: returnLast.arrival_time,
      duration_minutes: returnDuration,
      stops: Math.max(0, returnSegments.length - 1)
    } : null,
    outbound_segments: outboundSegments,
    return_segments: returnSegments,
    expires_at: offer.expires_at || null,
    live_mode: offer.live_mode === true
  };
}

async function request(path, options = {}) {
  const token = String(process.env.DUFFEL_ACCESS_TOKEN || '').trim();
  if (!token || /^(COLE_AQUI|SUBSTITUA|YOUR_|CHANGE_ME)/i.test(token) || !token.startsWith('duffel_live_')) {
    throw new FlightProviderError('É necessário configurar um token Duffel live válido para consultar preços reais.', 503, 'LIVE_TOKEN_REQUIRED');
  }
  let response;
  try {
    response = await fetch(`${API_BASE()}${path}`, {
      ...options,
      signal: AbortSignal.timeout(18000),
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'Duffel-Version': 'v2',
        ...(options.headers || {})
      }
    });
  } catch (error) {
    const timedOut = error?.name === 'TimeoutError';
    throw new FlightProviderError(timedOut ? 'A fonte de voos demorou demais para responder. Tente novamente.' : 'Não foi possível conectar à fonte de voos.', 502, timedOut ? 'PROVIDER_TIMEOUT' : 'PROVIDER_UNREACHABLE');
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const providerCode = payload?.errors?.[0]?.code || payload?.errors?.[0]?.type || 'PROVIDER_ERROR';
    const status = response.status === 429 ? 503 : response.status >= 500 ? 502 : 422;
    const message = response.status === 429
      ? 'A fonte de voos atingiu seu limite temporário. Tente novamente mais tarde.'
      : response.status >= 500
        ? 'A fonte de voos está temporariamente indisponível.'
        : 'A fonte de voos não aceitou esta pesquisa. Confira os aeroportos e as datas.';
    console.error('[flight-provider] Duffel request failed', { status: response.status, providerCode });
    throw new FlightProviderError(message, status, String(providerCode));
  }
  return payload?.data;
}

export async function searchDuffelOffers({ origin, destination, departureDate, returnDate, passengers = 1, cabin = 'economy' }) {
  const slices = [{ origin, destination, departure_date: departureDate }];
  if (returnDate) slices.push({ origin: destination, destination: origin, departure_date: returnDate });
  const data = await request('/air/offer_requests?return_offers=true', {
    method: 'POST',
    body: JSON.stringify({ data: {
      slices,
      passengers: Array.from({ length: passengers }, () => ({ type: 'adult' })),
      cabin_class: ['economy', 'premium_economy', 'business', 'first'].includes(cabin) ? cabin : 'economy',
      payment_currency: CURRENCY()
    } })
  });
  let offers = Array.isArray(data?.offers) ? data.offers : [];
  if (!offers.length && data?.id) {
    const fetched = await request(`/air/offer_requests/${encodeURIComponent(data.id)}?view=offers`);
    offers = Array.isArray(fetched?.offers) ? fetched.offers : [];
  }
  const maxResults = Math.min(50, Math.max(1, Number(process.env.FLIGHT_MAX_RESULTS || 30)));
  return offers.map(normalizeDuffelOffer).filter(Boolean).filter(offer => offer.live_mode === true).sort((a, b) => a.price - b.price).slice(0, maxResults);
}

export async function getDuffelOffer(offerId) {
  const id = String(offerId || '').trim();
  if (!/^off_[A-Za-z0-9]+$/.test(id)) throw new FlightProviderError('A oferta selecionada não é válida. Faça uma nova pesquisa.', 400, 'INVALID_OFFER_ID');
  const offer = await request(`/air/offers/${encodeURIComponent(id)}`);
  const normalized = normalizeDuffelOffer(offer);
  if (!normalized || normalized.live_mode !== true) throw new FlightProviderError('A oferta não está disponível para cotação ao vivo. Faça uma nova pesquisa.', 409, 'OFFER_NOT_LIVE');
  return normalized;
}
