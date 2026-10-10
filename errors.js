export class FlightProviderError extends Error {
  constructor(message, statusCode = 502, code = 'PROVIDER_ERROR') {
    super(message);
    this.name = 'FlightProviderError';
    this.statusCode = statusCode;
    this.code = code;
  }
}
