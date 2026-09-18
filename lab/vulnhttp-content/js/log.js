// CVE-2021-33558 (Boa 0.94.13) info disclosure: js/log.js accesible sin auth.
// Datos PLANTADOS para el lab — no son reales.
// Log de sesiones administrativas expuesto:
var SESSION_LOG = [
  { ts: "2024-11-02T08:14:03", user: "admin", ip: "192.168.1.10", action: "login" },
  { ts: "2024-11-02T08:15:41", user: "admin", ip: "192.168.1.10", action: "change_wifi_psk", new_psk: "admin12345" }
];
