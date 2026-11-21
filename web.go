package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type ParsedData struct {
	Timestamp      string  `json:"timestamp"`
	EquipmentID    string  `json:"equipment_id"`
	PowerDelivered float64 `json:"power_delivered"`
	PowerReturned  float64 `json:"power_returned"`
	EnergyT1In     float64 `json:"energy_t1_in"`
	EnergyT2In     float64 `json:"energy_t2_in"`
	EnergyT1Out    float64 `json:"energy_t1_out"`
	EnergyT2Out    float64 `json:"energy_t2_out"`
	VoltageL1      float64 `json:"voltage_l1"`
	CurrentL1      float64 `json:"current_l1"`
	GasDelivered   float64 `json:"gas_delivered"`
	RawTelegram    string  `json:"raw_telegram"`
}

type WebServer struct {
	mu          sync.RWMutex
	latest      ParsedData
	subscribers map[chan ParsedData]struct{}
}

var (
	rePowerDelivered = regexp.MustCompile(`1-0:1\.7\.0\(([0-9.]+)\*k?W\)`)
	rePowerReturned  = regexp.MustCompile(`1-0:2\.7\.0\(([0-9.]+)\*k?W\)`)
	reT1In           = regexp.MustCompile(`1-0:1\.8\.1\(([0-9.]+)\*kWh\)`)
	reT2In           = regexp.MustCompile(`1-0:1\.8\.2\(([0-9.]+)\*kWh\)`)
	reT1Out          = regexp.MustCompile(`1-0:2\.8\.1\(([0-9.]+)\*kWh\)`)
	reT2Out          = regexp.MustCompile(`1-0:2\.8\.2\(([0-9.]+)\*kWh\)`)
	reVoltageL1      = regexp.MustCompile(`1-0:32\.7\.0\(([0-9.]+)\*V\)`)
	reCurrentL1      = regexp.MustCompile(`1-0:31\.7\.0\(([0-9.]+)\*A\)`)
	reGas            = regexp.MustCompile(`0-[1-9]:24\.2\.1\(.+?\)\(([0-9.]+)\*m3\)`)
	reEquipmentID    = regexp.MustCompile(`0-0:96\.1\.1\(([0-9A-Fa-f]+)\)`)
)

func NewWebServer() *WebServer {
	return &WebServer{
		subscribers: make(map[chan ParsedData]struct{}),
	}
}

func parseTelegram(raw string) ParsedData {
	data := ParsedData{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		RawTelegram: raw,
	}

	extractFloat := func(re *regexp.Regexp) float64 {
		m := re.FindStringSubmatch(raw)
		if len(m) > 1 {
			val, _ := strconv.ParseFloat(m[1], 64)
			return val
		}
		return 0.0
	}

	if m := reEquipmentID.FindStringSubmatch(raw); len(m) > 1 {
		data.EquipmentID = m[1]
	}

	data.PowerDelivered = extractFloat(rePowerDelivered)
	data.PowerReturned = extractFloat(rePowerReturned)
	data.EnergyT1In = extractFloat(reT1In)
	data.EnergyT2In = extractFloat(reT2In)
	data.EnergyT1Out = extractFloat(reT1Out)
	data.EnergyT2Out = extractFloat(reT2Out)
	data.VoltageL1 = extractFloat(reVoltageL1)
	data.CurrentL1 = extractFloat(reCurrentL1)
	data.GasDelivered = extractFloat(reGas)

	return data
}

func (ws *WebServer) Broadcast(rawTelegram string) {
	parsed := parseTelegram(rawTelegram)

	ws.mu.Lock()
	ws.latest = parsed
	ws.mu.Unlock()

	ws.mu.RLock()
	defer ws.mu.RUnlock()
	for ch := range ws.subscribers {
		select {
		case ch <- parsed:
		default:
		}
	}
}

func (ws *WebServer) Start(host string, port int) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/data", ws.handleAPI)
	mux.HandleFunc("/events", ws.handleSSE)

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Starting web dashboard on http://%s\n", addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("dashboard").Parse(htmlDashboardTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ws.mu.RLock()
	data := ws.latest
	ws.mu.RUnlock()
	_ = tmpl.Execute(w, data)
}

func (ws *WebServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws.latest)
}

func (ws *WebServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan ParsedData, 10)
	ws.mu.Lock()
	ws.subscribers[ch] = struct{}{}
	initial := ws.latest
	ws.mu.Unlock()

	defer func() {
		ws.mu.Lock()
		delete(ws.subscribers, ch)
		close(ch)
		ws.mu.Unlock()
	}()

	if initial.RawTelegram != "" {
		b, _ := json.Marshal(initial)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-ch:
			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

const htmlDashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Smart Meter Bridge — DSMR 5L Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: #0f172a; --card-bg: #1e293b; --text: #f8fafc;
      --accent: #38bdf8; --accent-green: #4ade80; --border: #334155;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
    h1 { margin: 0; font-size: 1.5rem; display: flex; align-items: center; gap: 8px; }
    .badge { font-size: 0.75rem; background: var(--accent); color: #000; padding: 2px 8px; border-radius: 999px; font-weight: bold; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
    .card .title { font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px; }
    .card .value { font-size: 1.8rem; font-weight: 700; color: var(--accent-green); }
    .card .unit { font-size: 1rem; color: #94a3b8; font-weight: 400; }
    pre { background: #000; border: 1px solid var(--border); padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; line-height: 1.4; color: #38bdf8; max-height: 380px; }
    .status-dot { width: 10px; height: 10px; background: #22c55e; border-radius: 50%; display: inline-block; box-shadow: 0 0 8px #22c55e; }
  </style>
</head>
<body>
  <header>
    <h1>Smart Meter Bridge <span class="badge">DSMR 5L</span></h1>
    <div>
      <span class="status-dot"></span> Live
      <span id="ts" style="margin-left: 10px; color: #94a3b8; font-size: 0.9rem;">Waiting for data...</span>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <div class="title">Current Power Consumption</div>
      <div class="value"><span id="power_del">0.00</span> <span class="unit">kW</span></div>
    </div>
    <div class="card">
      <div class="title">Current Power Production</div>
      <div class="value"><span id="power_ret">0.00</span> <span class="unit">kW</span></div>
    </div>
    <div class="card">
      <div class="title">Grid Voltage (L1)</div>
      <div class="value"><span id="volt">0.0</span> <span class="unit">V</span></div>
    </div>
    <div class="card">
      <div class="title">Grid Current (L1)</div>
      <div class="value"><span id="curr">0.0</span> <span class="unit">A</span></div>
    </div>
    <div class="card">
      <div class="title">Total Import (T1 + T2)</div>
      <div class="value"><span id="energy_in">0.0</span> <span class="unit">kWh</span></div>
    </div>
    <div class="card">
      <div class="title">Total Export (T1 + T2)</div>
      <div class="value"><span id="energy_out">0.0</span> <span class="unit">kWh</span></div>
    </div>
  </div>

  <h2>Latest Decrypted Telegram</h2>
  <pre id="raw">Waiting for incoming telegram...</pre>

  <script>
    const evtSource = new EventSource('/events');
    evtSource.onmessage = function(event) {
      const data = JSON.parse(event.data);
      document.getElementById('ts').innerText = data.timestamp;
      document.getElementById('power_del').innerText = data.power_delivered.toFixed(3);
      document.getElementById('power_ret').innerText = data.power_returned.toFixed(3);
      document.getElementById('volt').innerText = data.voltage_l1.toFixed(1);
      document.getElementById('curr').innerText = data.current_l1.toFixed(1);
      document.getElementById('energy_in').innerText = (data.energy_t1_in + data.energy_t2_in).toFixed(2);
      document.getElementById('energy_out').innerText = (data.energy_t1_out + data.energy_t2_out).toFixed(2);
      document.getElementById('raw').innerText = data.raw_telegram;
    };
  </script>
</body>
</html>`
