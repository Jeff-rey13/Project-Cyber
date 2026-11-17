# AeroScan

Authorization-gated DAST scanner for airline booking APIs. It refuses to scan any host you haven't proven you own. Ships with **Nimbus Air**, a fictional, deliberately vulnerable booking stack, as its only target.

> Status: skeleton. See `PRD.md` for the spec and build order.

## Run

```
cp .env.example .env
make up
```
