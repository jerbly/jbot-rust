### JBot in Rust
This is a rust implementation of [jbot](https://github.com/jerbly/jbot). This [guide](https://docs.microsoft.com/en-us/azure/azure-functions/create-first-function-vs-code-other?tabs=rust%2Clinux) was used.

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
### Deployment:
```
cargo build --release --target=x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/jbot .
```