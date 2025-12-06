# cryptonote-simple-signature js

# Using example `cryptonote-simple-signature`

## Signature

```ts
import { createSignature } from 'cryptonote-simple-signature';

const message = [
  'post',
  'http://localhost:3333/api/v1/auth/register',
  'Fri, 21 Feb 2025 03:04:19 GMT',
  '48c35187e5b6f2bb39214e1311d3d50f9d480bda56e7563fac689a1d867992a4'
].join(' ');

const privateKey = '80b3e96a3eb765332b0fd3e44e0fefa58747a70025bf91aa4a7b758ab6f5590d';

const signature = createSignature(message, privateKey);
```
