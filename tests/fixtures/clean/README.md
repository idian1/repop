# weather-api-demo

A small Express service that proxies the public Open-Meteo weather API.

## Running locally

```
npm install
npm start
```

Then hit `http://localhost:3000/weather?latitude=52.52&longitude=13.41`.

Configuration is read from environment variables (`PORT`, `WEATHER_API_URL`,
`NODE_ENV`). No build step, no native modules, no install scripts.

> This is a beavertrap test fixture representing a *benign* project. It uses
> `axios` and `process.env` and the ordinary "run npm install then npm start"
> instructions on purpose — to confirm those everyday patterns do not produce
> a false CRITICAL verdict.
