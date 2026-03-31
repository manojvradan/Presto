# Setup



## Getting started

1. You may need to modify the path 110-112 in `api/index.js` depending on where your frontend folder is:
```js
const port = USE_VERCEL_KV
  ? PROD_BACKEND_PORT
  : JSON.parse(fs.readFileSync("../frontend/backend.config.json")).BACKEND_PORT;

```
2. Run these commands:
```
npm i
```

```
npm run start
```