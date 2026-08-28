// A perfectly ordinary Express app. Uses axios for outbound HTTP and reads
// configuration from process.env. This exists to prove that legitimate,
// common patterns (a web framework + an HTTP client + env-based config) do
// NOT trip beavertrap into a false positive.

const express = require("express");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 3000;
const UPSTREAM = process.env.WEATHER_API_URL || "https://api.open-meteo.com/v1/forecast";

app.get("/health", (req, res) => {
  res.json({ status: "ok", env: process.env.NODE_ENV || "development" });
});

app.get("/weather", async (req, res) => {
  try {
    const { latitude = 52.52, longitude = 13.41 } = req.query;
    const response = await axios.get(UPSTREAM, {
      params: { latitude, longitude, current_weather: true },
    });
    res.json(response.data);
  } catch (err) {
    res.status(502).json({ error: "upstream request failed" });
  }
});

app.listen(PORT, () => {
  console.log(`weather-api-demo listening on port ${PORT}`);
});
