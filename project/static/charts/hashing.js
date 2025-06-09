export async function renderCharts() {
  const container = document.getElementById('charts-container');
  container.innerHTML = ''; // Czyść poprzednie wykresy

  const stats = await fetchStatsData();
  const data = stats.filter(entry => entry.status === 'success');

  const registerData = data.filter(d => d.action === 'register');
  const loginData = data.filter(d => d.action === 'login');

  // Helper do średnich
  function avg(values) {
    if (!values.length) return 0;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  // ----- 1. Algorytm -----
  const algorithms = [...new Set(data.map(d => d.algorithm))];

  const encryptionTimesAlg = algorithms.map(alg => {
    const values = registerData.filter(d => d.algorithm === alg).map(d => d.encryptionTime || 0);
    return avg(values);
  });

  const decryptionTimesAlg = algorithms.map(alg => {
    const values = loginData.filter(d => d.algorithm === alg).map(d => d.decryptionTime || 0);
    return avg(values);
  });

  createBarChart(container, 'encryption-decryption-algorithm', 'Encryption vs Decryption vs Algorithm', algorithms, encryptionTimesAlg, decryptionTimesAlg);

  // ----- 2. Długość klucza -----
  const keyLengths = [...new Set(data.map(d => d.keyLength))].sort((a, b) => a - b);

  const encryptionTimesKey = keyLengths.map(len => {
    const values = registerData.filter(d => d.keyLength === len).map(d => d.encryptionTime || 0);
    return avg(values);
  });

  const decryptionTimesKey = keyLengths.map(len => {
    const values = loginData.filter(d => d.keyLength === len).map(d => d.decryptionTime || 0);
    return avg(values);
  });

  createBarChart(container, 'encryption-decryption-keylength', 'Encryption vs Decryption vs Key Length', keyLengths.map(String), encryptionTimesKey, decryptionTimesKey);

  // ----- 3. Długość wiadomości -----
  const msgLengths = [...new Set(data.map(d => d.messageLength))].sort((a, b) => a - b);

  const encryptionTimesMsg = msgLengths.map(len => {
    const values = registerData.filter(d => d.messageLength === len).map(d => d.encryptionTime || 0);
    return avg(values);
  });

  const decryptionTimesMsg = msgLengths.map(len => {
    const values = loginData.filter(d => d.messageLength === len).map(d => d.decryptionTime || 0);
    return avg(values);
  });

  createBarChart(container, 'encryption-decryption-msglength', 'Encryption vs Decryption vs Message Length', msgLengths.map(String), encryptionTimesMsg, decryptionTimesMsg);
}

function createBarChart(container, id, title, labels, encryptionData, decryptionData) {
  const canvas = document.createElement('canvas');
  canvas.id = id;
  canvas.style.maxWidth = '1400px';
  canvas.style.margin = '30px auto';
  container.appendChild(canvas);

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Encryption (register)',
          backgroundColor: 'rgba(54, 162, 235, 0.6)',
          borderColor: 'rgba(54, 162, 235, 1)',
          borderWidth: 1,
          data: encryptionData
        },
        {
          label: 'Decryption (login)',
          backgroundColor: 'rgba(255, 99, 132, 0.6)',
          borderColor: 'rgba(255, 99, 132, 1)',
          borderWidth: 1,
          data: decryptionData
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
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Czas (s)'
          }
        },
        x: {
          title: {
            display: true,
            text: 'Wartości'
          }
        }
      }
    }
  });
}

async function fetchStatsData() {
  const response = await fetch('/stats/data');
  if (!response.ok) throw new Error('Błąd pobierania danych');
  return response.json();
}
