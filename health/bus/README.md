# health/bus

Message-bus connectivity health check for [`health.Checker`](..), probing
any provider-agnostic connection value shaped like
[`message-bus-golang`](https://github.com/JinishBhardwaj/message-bus-golang)'s
`bus.Connection` — without this package depending on that module.

```go
func Check(conn Connection, tags ...string) health.Check
```

`Connection` is a local, one-method interface (`Connect(ctx) error`) matched
structurally by any concrete adapter. The probe relies on `Connect` being
documented as an idempotent no-op when already connected, so calling it
again is a safe, side-effect-free liveness check.

## Usage

```go
checker := health.NewChecker()
checker.Register("rabbitmq", bus.Check(conn, "bus", "ready"))
```
