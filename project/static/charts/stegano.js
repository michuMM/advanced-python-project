// static/charts/stegano.js

export function renderCharts(data) {
  const chartsContainer = document.getElementById('charts-container');

  const filtered = data.filter(item => item.status === 'success');

  const byAlgorithm = {};
  const byFormat = {};
  const byMessageLength = {};

  for (const item of filtered) {
    const { algorithm, fileFormat, encodingTime, decodingTime, messageLength } = item;

    // By Algorithm
    if (!byAlgorithm[algorithm]) byAlgorithm[algorithm] = { enc: [], dec: [] };
    if (encodingTime) byAlgorithm[algorithm].enc.push(encodingTime);
    if (decodingTime) byAlgorithm[algorithm].dec.push(decodingTime);

    // By Format
    if (!byFormat[fileFormat]) byFormat[fileFormat] = { enc: [], dec: [] };
    if (encodingTime) byFormat[fileFormat].enc.push(encodingTime);
    if (decodingTime) byFormat[fileFormat].dec.push(decodingTime);

    // By Message Length (rounded to bin)
    const bin = Math.floor(messageLength / 10) * 10;
    if (!byMessageLength[bin]) byMessageLength[bin] = { enc: [], dec: [] };
    if (encodingTime) byMessageLength[bin].enc.push(encodingTime);
    if (decodingTime) byMessageLength[bin].dec.push(decodingTime);
  }

  function avg(arr) {
    if (!arr.length) return 0;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  function createChart(title, labels, encData, decData) {
    const canvas = document.createElement('canvas');
    chartsContainer.appendChild(canvas);

    new Chart(canvas.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Encoding Time (s)',
            backgroundColor: 'rgba(54, 162, 235, 0.6)',
            data: encData,
          },
          {
            label: 'Decoding Time (s)',
            backgroundColor: 'rgba(255, 99, 132, 0.6)',
            data: decData,
          }
        ]
      },
      options: {
        responsive: true,
        plugins: {
          title: {
            display: true,
            text: title
          }
        }
      }
    });
  }

  // 1. Encoding/Decoding vs Algorithm
  const algLabels = Object.keys(byAlgorithm);
  const algEnc = algLabels.map(a => avg(byAlgorithm[a].enc));
  const algDec = algLabels.map(a => avg(byAlgorithm[a].dec));
  createChart('Encoding/Decoding Time vs Algorithm', algLabels, algEnc, algDec);

  // 2. Encoding/Decoding vs File Format
  const formatLabels = Object.keys(byFormat);
  const formatEnc = formatLabels.map(f => avg(byFormat[f].enc));
  const formatDec = formatLabels.map(f => avg(byFormat[f].dec));
  createChart('Encoding/Decoding Time vs File Format', formatLabels, formatEnc, formatDec);

  // 3. Encoding/Decoding vs Message Length
  const lengthBins = Object.keys(byMessageLength).sort((a, b) => parseInt(a) - parseInt(b));
  const lengthEnc = lengthBins.map(bin => avg(byMessageLength[bin].enc));
  const lengthDec = lengthBins.map(bin => avg(byMessageLength[bin].dec));
  createChart('Encoding/Decoding Time vs Message Length (binned)', lengthBins.map(bin => `${bin}-${+bin + 9}`), lengthEnc, lengthDec);
}
