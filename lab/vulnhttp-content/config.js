// CVE-2021-33558 (Boa 0.94.13) info disclosure: config.js accesible sin auth.
// Secretos PLANTADOS para el lab — no son credenciales reales.
var DEVICE_CONFIG = {
  model: "VulnRouter-X1000",
  firmware: "1.2.3",
  admin: { user: "admin", pass: "Sup3rS3cret!2024" },
  admin_url: "/admin/",          // panel admin (HTTP Basic) — usar las creds de arriba
  api_token: "eyJhbGciOiJIUzI1Ni␣FAKE.lab.token",
  mqtt: { host: "127.0.0.1", anonymous: true }
};
