import { FlightProviderError } from './errors.js';

const API_BASE = 'https://ignav.com/api';
const offerCache = new Map();
const MAX_CACHE_ITEMS = 500;

function durationMinutes(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.round(value);
  const text = String(value || '');
  if (/^P/i.test(text)) {
    const m = text.match(/^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?$/i);
    if (m) return Number(m[1] || 0) * 1440 + Number(m[2] || 0) * 60 + Number(m[3] || 0);
  }
  const hm = text.match(/(?:(\d+)h)?\s*(?:(\d+)m)?/i);
  return hm && (hm[1] || hm[2]) ? Number(hm[1] || 0) * 60 + Number(hm[2] || 0) : 0;
}
function clock(value) {
  if (!value) return '';
  const s = String(value);
  const iso = s.match(/T(\d{2}:\d{2})/);
  if (iso) return iso[1];
  const hm = s.match(/\b(\d{1,2}:\d{2})\b/);
  return hm ? hm[1].padStart(5, '0') : s;
}
function datePart(value) { return value ? String(value).slice(0, 10) : ''; }
function segmentView(segment = {}) {
  const from = segment.origin || segment.from || segment.departure_airport || {};
  const to = segment.destination || segment.to || segment.arrival_airport || {};
  const airline = segment.airline || segment.carrier || {};
  const originCode = segment.origin_code || segment.from_iata || from.iata_code || from.code || segment.departure_iata || '';
  const destinationCode = segment.destination_code || segment.to_iata || to.iata_code || to.code || segment.arrival_iata || '';
  const dep = segment.departure_time || segment.departure_at || segment.departure_time_local || segment.departure_datetime || '';
  const arr = segment.arrival_time || segment.arrival_at || segment.arrival_time_local || segment.arrival_datetime || '';
  const airlineName = segment.airline_name || airline.name || segment.carrier_name || '';
  const airlineCode = segment.airline_code || airline.iata_code || segment.carrier_code || '';
  const flightNo = segment.flight_number || segment.flight_code || segment.number || '';
  return {
    airline_name: airlineName || 'Companhia não informada pela fonte',
    airline_code: airlineCode,
    flight_code: `${airlineCode}${flightNo ? ` ${flightNo}` : ''}`.trim(),
    origin_city: segment.origin_city || from.city || from.city_name || originCode,
    origin_code: originCode,
    destination_city: segment.destination_city || to.city || to.city_name || destinationCode,
    destination_code: destinationCode,
    departure_time: clock(dep), arrival_time: clock(arr),
    departure_at: dep || null, arrival_at: arr || null,
    duration_minutes: durationMinutes(segment.duration_minutes ?? segment.duration),
    aircraft: segment.aircraft_name || segment.aircraft || null,
    departure_airport: segment.departure_airport_name || from.name || null,
    arrival_airport: segment.arrival_airport_name || to.name || null
  };
}
function getSegments(itinerary, direction) {
  const raw = direction === 'return'
    ? (itinerary.inbound_segments || itinerary.return_segments || itinerary.inbound?.segments || itinerary.return?.segments || itinerary.inbound || [])
    : (itinerary.outbound_segments || itinerary.outbound?.segments || itinerary.segments || itinerary.flights || []);
  return Array.isArray(raw) ? raw.map(segmentView) : [];
}
function normalizeIgnavOffer(itinerary, params = {}) {
  const outbound = getSegments(itinerary, 'outbound');
  const inbound = getSegments(itinerary, 'return');
  const first = outbound[0], last = outbound[outbound.length - 1];
  if (!first || !last) return null;
  const rawPrice = itinerary.price;
  const amount = Number(typeof rawPrice === 'object' ? rawPrice.amount : (itinerary.price_amount ?? rawPrice));
  const currency = String((typeof rawPrice === 'object' && rawPrice.currency) || itinerary.currency || 'BRL').toUpperCase();
  if (!Number.isFinite(amount) || amount < 0) return null;
  const ignavId = String(itinerary.ignav_id || itinerary.id || itinerary.offer_id || '').trim();
  if (!ignavId) return null;
  const status = typeof rawPrice === 'object' ? rawPrice.status : itinerary.price_status;
  if (status && !['verified', 'live', 'available', 'confirmed'].includes(String(status).toLowerCase())) return null;
  const retFirst = inbound[0], retLast = inbound[inbound.length - 1];
  const id = `ignav:${ignavId}`;
  const offer = {
    id, provider_offer_id: ignavId, source_type: 'provider', source: 'Ignav',
    airline_name: first.airline_name, flight_code: first.flight_code || 'Voo informado pela fonte',
    origin_city: first.origin_city, origin_code: first.origin_code,
    destination_city: last.destination_city, destination_code: last.destination_code,
    departure_date: datePart(first.departure_at) || params.departureDate || datePart(itinerary.departure_date),
    return_date: retFirst ? (datePart(retFirst.departure_at) || params.returnDate || datePart(itinerary.return_date)) : null,
    departure_time: first.departure_time, arrival_time: last.arrival_time,
    duration_minutes: durationMinutes(itinerary.duration_minutes) || outbound.reduce((sum, s) => sum + s.duration_minutes, 0),
    stops: Math.max(0, outbound.length - 1),
    cabin: itinerary.cabin_class || itinerary.cabin || params.cabin || 'Econômica',
    price: amount, currency, passenger_count: params.passengers || itinerary.passenger_count || null,
    return_info: retFirst && retLast ? { airline_name: retFirst.airline_name, flight_code: retFirst.flight_code, origin_city: retFirst.origin_city, origin_code: retFirst.origin_code, destination_city: retLast.destination_city, destination_code: retLast.destination_code, departure_time: retFirst.departure_time, arrival_time: retLast.arrival_time, duration_minutes: inbound.reduce((sum, s) => sum + s.duration_minutes, 0), stops: Math.max(0, inbound.length - 1) } : null,
    outbound_segments: outbound, return_segments: inbound,
    price_status: status || null, expires_at: itinerary.expires_at || null, live_mode: true
  };
  return offer;
}
async function request(path, body) {
  const key = String(process.env.IGNAV_API_KEY || '').trim();
  if (!key || /^(COLE_AQUI|SUBSTITUA|YOUR_|CHANGE_ME)/i.test(key)) throw new FlightProviderError('Configure IGNAV_API_KEY no ambiente do servidor para ativar a busca automática.', 503, 'IGNAV_KEY_REQUIRED');
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Api-Key': key }, body: JSON.stringify(body), signal: AbortSignal.timeout(18000) });
  } catch (error) {
    const timeout = error?.name === 'TimeoutError';
    throw new FlightProviderError(timeout ? 'A busca de voos demorou demais. Tente novamente.' : 'Não foi possível conectar à fonte de voos.', 502, timeout ? 'IGNAV_TIMEOUT' : 'IGNAV_UNREACHABLE');
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error('[flight-provider] Ignav request failed', { status: response.status, code: payload?.code || payload?.error?.code || 'IGNAV_ERROR' });
    const status = response.status === 429 ? 503 : response.status >= 500 ? 502 : 422;
    throw new FlightProviderError(response.status === 429 ? 'A fonte de voos atingiu um limite temporário. Tente mais tarde.' : 'A fonte de voos não aceitou esta pesquisa. Confira os aeroportos, datas e credenciais.', status, 'IGNAV_REQUEST_FAILED');
  }
  return payload;
}
export async function searchIgnavOffers(params) {
  const body = {
    origin: params.origin, destination: params.destination,
    departure_date: params.departureDate,
    adults: params.passengers || 1,
    cabin_class: ['economy','premium_economy','business','first'].includes(params.cabin) ? params.cabin : 'economy',
    market: String(process.env.FLIGHT_MARKET || 'BR').toUpperCase()
  };
  const path = params.returnDate ? '/fares/round-trip' : '/fares/one-way';
  if (params.returnDate) body.return_date = params.returnDate;
  const payload = await request(path, body);
  const itineraries = Array.isArray(payload?.itineraries) ? payload.itineraries : Array.isArray(payload?.data?.itineraries) ? payload.data.itineraries : [];
  const maxResults = Math.min(50, Math.max(1, Number(process.env.FLIGHT_MAX_RESULTS || 30)));
  const offers = itineraries.map(item => normalizeIgnavOffer(item, params)).filter(Boolean).sort((a,b) => a.price-b.price).slice(0, maxResults);
  for (const offer of offers) {
    offerCache.set(offer.provider_offer_id, { offer, savedAt: Date.now() });
    if (offerCache.size > MAX_CACHE_ITEMS) offerCache.delete(offerCache.keys().next().value);
  }
  return offers;
}
export async function getIgnavOffer(offerId) {
  const id = String(offerId || '').trim();
  const cached = offerCache.get(id);
  if (!cached || Date.now() - cached.savedAt > 3 * 60 * 60 * 1000) {
    throw new FlightProviderError('Esta oferta não está mais na sessão de busca. Pesquise novamente para confirmar os dados.', 409, 'IGNAV_OFFER_EXPIRED');
  }
  return cached.offer;
}
