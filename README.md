### Local testing:
**Server**
```
cargo build --release
cp target/release/jbot .
func start --verbose
```
**Client**
```
curl -X POST http://localhost:7071/api/TeamsTrigger -H 'Content-Type: application/json' -H 'Authorization: HMAC tqSwGtJVnQbecZogqfLxZd/GNOFCm2Fp0Ikyr6utmCc=' -d '{"type":"message","text":"Ticket one is BACKLOG-1234 and two is MED-789"}'
```