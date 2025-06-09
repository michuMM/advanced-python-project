// time.js

export async function renderCharts(statsData) {
  const filtered = statsData.filter(d => d.status !== 'fail');

  // Generujemy HTML z canvaseami w divie #charts-container
  const container = document.getElementById('charts-container');
  container.innerHTML = `
    <canvas id="chart-time-algorithm" style="max-width:600px; margin-bottom:40px;"></canvas>
    <canvas id="chart-time-operation-share" style="max-width:600px; margin-bottom:40px;"></canvas>
    <canvas id="chart-time-keylen" style="max-width:600px; margin-bottom:40px;"></canvas>
    <canvas id="chart-time-msglen" style="max-width:600px; margin-bottom:40px;"></canvas>
  `;

  // Funkcje pomocnicze do wykresów:
  function createBarChart(ctx, labels, data, title, xLabel, yLabel) {
    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: yLabel,
          data,
          backgroundColor: 'rgba(31, 111, 235, 0.7)',
          borderColor: 'rgba(31, 111, 235, 1)',
          borderWidth: 1,
          borderRadius: 5
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
          title: { display: true, text: title, font: { size: 18 } }
        },
        scales: {
          x: { title: { display: true, text: xLabel } },
          y: { title: { display: true, text: yLabel }, beginAtZero: true }
        }
      }
    });
  }

  function createPieChart(ctx, labels, data, title) {
    return new Chart(ctx, {
      type: 'pie',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: [
            'rgba(31, 111, 235, 0.7)',
            'rgba(31, 200, 235, 0.7)',
            'rgba(235, 111, 31, 0.7)'
          ],
          borderColor: 'rgba(255,255,255,0.6)',
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom' },
          title: { display: true, text: title, font: { size: 18 } }
        }
      }
    });
  }

  // 1. total time vs algorytm (średni)
  const timeByAlg = {};
  filtered.forEach(({ algorithm, totalTime }) => {
    if (!timeByAlg[algorithm]) timeByAlg[algorithm] = { sum: 0, count: 0 };
    timeByAlg[algorithm].sum += totalTime;
    timeByAlg[algorithm].count++;
  });
  const algorithms = Object.keys(timeByAlg);
  const avgTimesAlg = algorithms.map(a => timeByAlg[a].sum / timeByAlg[a].count);

  // 2. udział w enkrypcji, enkodowaniu i reszcie operacji dla pierwszego algorytmu
  const chosenAlg = algorithms[0] || null;
  let encPercent = 0, encodPercent = 0, otherPercent = 0;
  if (chosenAlg) {
    const filteredAlg = filtered.filter(d => d.algorithm === chosenAlg);
    let encSum = 0, encodSum = 0, otherSum = 0;
    filteredAlg.forEach(({ encryptionTime = 0, encodingTime = 0, otherTime = 0 }) => {
      encSum += encryptionTime;
      encodSum += encodingTime;
      otherSum += otherTime;
    });
    const sumAll = encSum + encodSum + otherSum || 1; // żeby nie dzielić przez 0
    encPercent = (encSum / sumAll) * 100;
    encodPercent = (encodSum / sumAll) * 100;
    otherPercent = (otherSum / sumAll) * 100;
  }

  // 3. total time vs długość klucza (średni)
  const timeByKeyLen = {};
  filtered.forEach(({ keyLength, totalTime }) => {
    if (!timeByKeyLen[keyLength]) timeByKeyLen[keyLength] = { sum: 0, count: 0 };
    timeByKeyLen[keyLength].sum += totalTime;
    timeByKeyLen[keyLength].count++;
  });
  const keyLengths = Object.keys(timeByKeyLen).sort((a, b) => a - b);
  const avgTimesKeyLen = keyLengths.map(k => timeByKeyLen[k].sum / timeByKeyLen[k].count);

  // 4. total time vs długość wiadomości (średni)
  const timeByMsgLen = {};
  filtered.forEach(({ messageLength, totalTime }) => {
    if (!timeByMsgLen[messageLength]) timeByMsgLen[messageLength] = { sum: 0, count: 0 };
    timeByMsgLen[messageLength].sum += totalTime;
    timeByMsgLen[messageLength].count++;
  });
  const msgLengths = Object.keys(timeByMsgLen).sort((a, b) => a - b);
  const avgTimesMsgLen = msgLengths.map(m => timeByMsgLen[m].sum / timeByMsgLen[m].count);

  // Rysujemy wykresy
  createBarChart(
    document.getElementById('chart-time-algorithm').getContext('2d'),
    algorithms,
    avgTimesAlg,
    'Średni total time wg algorytmu',
    'Algorytm',
    'Czas [ms]'
  );

  if (chosenAlg) {
    createPieChart(
      document.getElementById('chart-time-operation-share').getContext('2d'),
      ['Enkrypcja', 'Enkodowanie', 'Pozostałe'],
      [encPercent, encodPercent, otherPercent],
      `Średni udział operacji dla algorytmu ${chosenAlg}`
    );
  }

  createBarChart(
    document.getElementById('chart-time-keylen').getContext('2d'),
    keyLengths,
    avgTimesKeyLen,
    'Średni total time wg długości klucza',
    'Długość klucza [bit]',
    'Czas [ms]'
  );

  createBarChart(
    document.getElementById('chart-time-msglen').getContext('2d'),
    msgLengths,
    avgTimesMsgLen,
    'Średni total time wg długości wiadomości',
    'Długość wiadomości [bajty]',
    'Czas [ms]'
  );
}
