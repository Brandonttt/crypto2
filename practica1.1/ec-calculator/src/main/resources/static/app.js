import { EllipticCurveAPI } from './ec-api-client.js';

const inputA = document.getElementById('inputA');
const inputB = document.getElementById('inputB');
const inputP = document.getElementById('inputP');
const btnValidate = document.getElementById('btnValidate');
const validationResult = document.getElementById('validationResult');

const selectP = document.getElementById('selectP');
const selectQ = document.getElementById('selectQ');
const btnAdd = document.getElementById('btnAdd');

const outputConsole = document.getElementById('outputConsole');
const groupOrderLabel = document.getElementById('groupOrder');
const totalPointsLabel = document.getElementById('totalPoints');

let currentCurve = null;
let currentPoints = [];

function getCurveFromInputs() {
  return {
    a: BigInt(inputA.value),
    b: BigInt(inputB.value),
    p: BigInt(inputP.value)
  };
}

function parsePointOption(val) {
  if (val === 'O') return { isInfinity: true };
  const [x, y] = val.split(',').map(n => BigInt(n));
  return { x, y, isInfinity: false };
}

function populateSelects(points) {
  const optionsHtml = [
    '<option value="O">Punto al Infinito (𝒪)</option>',
    ...points.map(pt => `<option value="${pt.x},${pt.y}">(${pt.x}, ${pt.y})</option>`)
  ].join('');

  selectP.innerHTML = optionsHtml;
  selectQ.innerHTML = optionsHtml;

  if (points.length > 0) {
    selectP.selectedIndex = 1;
    selectQ.selectedIndex = points.length > 1 ? 2 : 1;
  }
}

function formatEquation(a, b, p) {
  const formatTerm = (coef, variable) => {
    if (coef === 0n) return '';
    const sign = coef > 0n ? '+ ' : '- ';
    const absVal = coef > 0n ? coef : -coef;
    const num = absVal === 1n && variable ? '' : absVal;
    return `${sign}${num}${variable} `;
  };

  let termA = formatTerm(a, 'x');
  let termB = formatTerm(b, '');
  let expr = `x³ ${termA}${termB}`.trim();
  return `y² ≡ ${expr} (mod ${p})`;
}

function renderCurveLoaded(curve, disc, totalPoints, affineCount) {
  const eqFormatted = formatEquation(curve.a, curve.b, curve.p);

  outputConsole.innerHTML = `
    <div class="alert-banner alert-success">
      <span>✔</span> Curva elíptica validada correctamente
    </div>

    <div class="equation-box">
      ${eqFormatted}
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-label">Discriminante (Δ)</div>
        <div class="metric-value">${disc}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Total Grupo #E(𝔽ₚ)</div>
        <div class="metric-value">${totalPoints}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Puntos Afines</div>
        <div class="metric-value">${affineCount}</div>
      </div>
    </div>
  `;
}

function renderOperationResult(title, details, resultText) {
  outputConsole.innerHTML = `
    <div class="alert-banner alert-info">
      <span>ℹ</span> ${title}
    </div>

    <div class="metrics-grid">
      ${details.map(d => `
        <div class="metric-card">
          <div class="metric-label">${d.label}</div>
          <div class="metric-value">${d.value}</div>
        </div>
      `).join('')}
    </div>

    <div class="metric-card" style="border-color: #3b82f6;">
      <div class="metric-label">Punto Resultante</div>
      <div class="metric-value" style="color: #60a5fa; font-size: 1.25rem;">${resultText}</div>
    </div>
  `;
}

function renderError(msg) {
  outputConsole.innerHTML = `
    <div class="alert-banner alert-danger">
      <span>✖</span> ${msg}
    </div>
  `;
}

// 1. Validar y Cargar Curva
btnValidate.addEventListener('click', async () => {
  try {
    currentCurve = getCurveFromInputs();

    const res = await EllipticCurveAPI.validateCurve(currentCurve.a, currentCurve.b, currentCurve.p);

    if (!res.valid) {
      validationResult.innerHTML = `<span class="status-badge invalid">${res.message}</span>`;
      renderError(`Curva singular: Discriminante Δ ≡ ${res.discriminant}`);
      return;
    }

    validationResult.innerHTML = `<span class="status-badge valid">${res.message}</span>`;

    const orderData = await EllipticCurveAPI.getGroupOrder(currentCurve.a, currentCurve.b, currentCurve.p);
    currentPoints = orderData.points;

    const totalGroupPoints = orderData.order;

    groupOrderLabel.textContent = totalGroupPoints;
    totalPointsLabel.textContent = `${totalGroupPoints} (${currentPoints.length} finitos + 𝒪)`;

    populateSelects(currentPoints);
    renderCurveLoaded(currentCurve, res.discriminant, totalGroupPoints, currentPoints.length);
  } catch (err) {
    renderError(`Fallo al cargar la curva: ${err.message}`);
  }
});

// 2. Suma P + Q
btnAdd.addEventListener('click', async () => {
  if (!currentCurve) {
    renderError('Carga primero una curva válida.');
    return;
  }

  try {
    const p1 = parsePointOption(selectP.value);
    const p2 = parsePointOption(selectQ.value);

    const res = await EllipticCurveAPI.addPoints(currentCurve, p1, p2);
    const ptR = res.result;

    const resultStr = ptR.isInfinity ? '𝒪 (Punto al Infinito)' : `(${ptR.x}, ${ptR.y})`;

    renderOperationResult('Suma de Puntos Realizada', [
      { label: 'Operación', value: res.operationType },
      { label: 'Pendiente (m)', value: res.slope ?? 'Indefinida' }
    ], resultStr);
  } catch (err) {
    renderError(`Error en la suma: ${err.message}`);
  }
});