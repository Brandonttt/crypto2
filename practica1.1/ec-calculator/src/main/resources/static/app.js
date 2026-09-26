import { EllipticCurveAPI } from './ec-api-client.js';

const inputA = document.getElementById('inputA');
const inputB = document.getElementById('inputB');
const inputP = document.getElementById('inputP');
const btnValidate = document.getElementById('btnValidate');
const validationResult = document.getElementById('validationResult');

const selectP = document.getElementById('selectP');
const selectQ = document.getElementById('selectQ');
const btnAdd = document.getElementById('btnAdd');
const btnDouble = document.getElementById('btnDouble');

const inputK = document.getElementById('inputK');
const btnMultiply = document.getElementById('btnMultiply');

const btnTableAdd = document.getElementById('btnTableAdd');
const btnTableMul = document.getElementById('btnTableMul');

const outputConsole = document.getElementById('outputConsole');
const cardinalityVal = document.getElementById('cardinalityVal');
const generatorsCount = document.getElementById('generatorsCount');
const generatorsList = document.getElementById('generatorsList');

const tableCard = document.getElementById('tableCard');
const tableTitle = document.getElementById('tableTitle');
const tableWrapper = document.getElementById('tableWrapper');
const allPointsList = document.getElementById('allPointsList');

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
    '<option value="O">𝒪 (Punto al Infinito)</option>',
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
  return `y² ≡ x³ ${termA}${termB}(mod ${p})`;
}

function renderError(msg) {
  outputConsole.innerHTML = `<div class="alert-banner alert-danger"><span>✖</span> ${msg}</div>`;
}

function renderOperationResult(title, details, resultText) {
  outputConsole.innerHTML = `
    <div class="alert-banner alert-info"><span>ℹ</span> ${title}</div>
    <div class="metrics-grid">
      ${details.map(d => `
        <div class="metric-card">
          <div class="metric-label">${d.label}</div>
          <div class="metric-value">${d.value}</div>
        </div>
      `).join('')}
    </div>
    <div class="metric-card" style="border-color:#3b82f6;">
      <div class="metric-label">Punto Resultante</div>
      <div class="metric-value" style="color:#60a5fa; font-size:1.2rem;">${resultText}</div>
    </div>
  `;
}

// 1. Validar curva y calcular cardinalidad + generadores
btnValidate.addEventListener('click', async () => {
  try {
    currentCurve = getCurveFromInputs();
    tableCard.style.display = 'none';

    const valRes = await EllipticCurveAPI.validateCurve(currentCurve.a, currentCurve.b, currentCurve.p);
    if (!valRes.valid) {
      validationResult.innerHTML = `<span class="status-badge invalid">${valRes.message}</span>`;
      renderError(`Curva singular. Δ ≡ ${valRes.discriminant}`);
      return;
    }
    validationResult.innerHTML = `<span class="status-badge valid">${valRes.message}</span>`;

    const analysis = await EllipticCurveAPI.analyzeGroup(currentCurve.a, currentCurve.b, currentCurve.p);
    currentPoints = analysis.points;

    // 1. Mostrar información del grupo
    cardinalityVal.textContent = analysis.cardinality;
    generatorsCount.textContent = analysis.generators.length;

    // 1. Mostrar TODOS los puntos del grupo (los afines + el punto al infinito)
    const fullPointsArray = ['𝒪', ...currentPoints.map(p => `(${p.x}, ${p.y})`)];
    allPointsList.textContent = fullPointsArray.join(', ');

    // 2. Mostrar únicamente los puntos generadores
    if (analysis.generators.length === 0) {
      generatorsList.textContent = 'El grupo no es cíclico o no posee generadores únicos.';
    } else {
      generatorsList.textContent = analysis.generators.map(g => `(${g.x}, ${g.y})`).join(', ');
    }

    populateSelects(currentPoints);

    outputConsole.innerHTML = `
      <div class="alert-banner alert-success"><span>✔</span> Curva validada y conjunto de puntos generado</div>
      <div class="equation-box">${formatEquation(currentCurve.a, currentCurve.b, currentCurve.p)}</div>
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">Discriminante Δ</div>
          <div class="metric-value">${valRes.discriminant}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Cardinalidad #E(𝔽ₚ)</div>
          <div class="metric-value">${analysis.cardinality}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Puntos Afines</div>
          <div class="metric-value">${currentPoints.length}</div>
        </div>
      </div>
    `;
  } catch (err) {
    renderError(`Fallo al cargar: ${err.message}`);
  }
});

// 2. Operaciones: Suma (P + Q)
btnAdd.addEventListener('click', async () => {
  if (!currentCurve) return renderError('Valida primero una curva.');
  try {
    const p1 = parsePointOption(selectP.value);
    const p2 = parsePointOption(selectQ.value);
    const res = await EllipticCurveAPI.addPoints(currentCurve, p1, p2);
    const ptR = res.result;
    const rLabel = ptR.isInfinity ? '𝒪' : `(${ptR.x}, ${ptR.y})`;

    renderOperationResult('Operación P + Q Realizada', [
      { label: 'Tipo', value: res.operationType },
      { label: 'Pendiente (m)', value: res.slope ?? 'Indefinida' }
    ], rLabel);
  } catch (err) {
    renderError(`Error en suma: ${err.message}`);
  }
});

// Doblado: 2P
btnDouble.addEventListener('click', async () => {
  if (!currentCurve) return renderError('Valida primero una curva.');
  try {
    const p1 = parsePointOption(selectP.value);
    const res = await EllipticCurveAPI.addPoints(currentCurve, p1, p1);
    const ptR = res.result;
    const rLabel = ptR.isInfinity ? '𝒪' : `(${ptR.x}, ${ptR.y})`;

    renderOperationResult('Doblado de Punto 2P Realizado', [
      { label: 'Tipo', value: res.operationType },
      { label: 'Pendiente (m)', value: res.slope ?? 'Indefinida' }
    ], rLabel);
  } catch (err) {
    renderError(`Error en doblado: ${err.message}`);
  }
});

// Multiplicación escalar: k · P
btnMultiply.addEventListener('click', async () => {
  if (!currentCurve) return renderError('Valida primero una curva.');
  try {
    const p1 = parsePointOption(selectP.value);
    const k = BigInt(inputK.value);
    const res = await EllipticCurveAPI.multiplyPoint(currentCurve, p1, k);
    const ptR = res.result;
    const rLabel = ptR.isInfinity ? '𝒪' : `(${ptR.x}, ${ptR.y})`;

    renderOperationResult('Multiplicación Escalar k · P', [
      { label: 'Escalar k', value: k.toString() },
      { label: 'Pasos', value: res.steps },
      { label: 'Bits', value: res.bitLength }
    ], rLabel);
  } catch (err) {
    renderError(`Error en multiplicación: ${err.message}`);
  }
});

// 3. Tablas
btnTableAdd.addEventListener('click', async () => {
  if (!currentCurve) return renderError('Valida primero una curva.');
  try {
    tableCard.style.display = 'block';
    tableTitle.textContent = 'Tabla de Suma de Puntos (Tabla de Cayley)';
    tableWrapper.innerHTML = 'Generando tabla de suma...';

    const data = await EllipticCurveAPI.getAdditionTable(currentCurve.a, currentCurve.b, currentCurve.p);

    let html = '<table><thead><tr><th class="left-col">+</th>';
    data.headers.forEach(h => { html += `<th>${h}</th>`; });
    html += '</tr></thead><tbody>';

    data.matrix.forEach((row, idx) => {
      html += `<tr><th class="left-col">${data.headers[idx]}</th>`;
      row.forEach(cell => { html += `<td>${cell}</td>`; });
      html += '</tr>';
    });
    html += '</tbody></table>';

    tableWrapper.innerHTML = html;
  } catch (err) {
    renderError(`Fallo al generar tabla de suma: ${err.message}`);
  }
});

btnTableMul.addEventListener('click', async () => {
  if (!currentCurve) return renderError('Valida primero una curva.');
  try {
    tableCard.style.display = 'block';
    tableTitle.textContent = 'Tabla de Multiplicación Escalar (k · P)';
    tableWrapper.innerHTML = 'Generando tabla escalar...';

    const data = await EllipticCurveAPI.getMultiplicationTable(currentCurve.a, currentCurve.b, currentCurve.p);

    let html = '<table><thead><tr><th class="left-col">Punto P</th>';
    data.scalarHeaders.forEach(h => { html += `<th>${h}</th>`; });
    html += '</tr></thead><tbody>';

    data.matrix.forEach((row, idx) => {
      html += `<tr><th class="left-col">${data.pointLabels[idx]}</th>`;
      row.forEach(cell => { html += `<td>${cell}</td>`; });
      html += '</tr>';
    });
    html += '</tbody></table>';

    tableWrapper.innerHTML = html;
  } catch (err) {
    renderError(`Fallo al generar tabla de multiplicación: ${err.message}`);
  }
});