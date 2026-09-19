const API_BASE_URL = '/api/ec';

export class EllipticCurveAPI {
  static async #request(endpoint, options = {}) {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(errorBody || `HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (err) {
      console.error(`Error invocando ${endpoint}:`, err);
      throw err;
    }
  }

  static async validateCurve(a, b, p) {
    return this.#request('/validate', {
      method: 'POST',
      body: JSON.stringify({ a: a.toString(), b: b.toString(), p: p.toString() }),
    });
  }

  static async getPoints(a, b, p) {
    const query = new URLSearchParams({
      a: a.toString(),
      b: b.toString(),
      p: p.toString(),
    });
    return this.#request(`/points?${query.toString()}`);
  }

  static async addPoints(curve, p1, p2) {
    return this.#request('/add', {
      method: 'POST',
      body: JSON.stringify({
        curve: { a: curve.a.toString(), b: curve.b.toString(), p: curve.p.toString() },
        p1: { x: p1.x?.toString() ?? null, y: p1.y?.toString() ?? null, isInfinity: !!p1.isInfinity },
        p2: { x: p2.x?.toString() ?? null, y: p2.y?.toString() ?? null, isInfinity: !!p2.isInfinity }
      }),
    });
  }

  static async multiplyPoint(curve, point, k) {
    return this.#request('/multiply', {
      method: 'POST',
      body: JSON.stringify({
        curve: { a: curve.a.toString(), b: curve.b.toString(), p: curve.p.toString() },
        point: { x: point.x?.toString() ?? null, y: point.y?.toString() ?? null, isInfinity: !!point.isInfinity },
        k: k.toString()
      }),
    });
  }

  static async getGroupOrder(a, b, p) {
    const query = new URLSearchParams({
      a: a.toString(),
      b: b.toString(),
      p: p.toString(),
    });
    return this.#request(`/order?${query.toString()}`);
  }
}