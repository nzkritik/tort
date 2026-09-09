# Screenshots

`tortunnel.png` is a real screenshot of the application with the relay details
replaced.

## What was replaced, and why

The original showed live circuits: the exit node's address, location and
operator, and the nicknames of all nine relays in use.

None of that is secret in itself — every relay in the Tor consensus is public.
What a screenshot adds is the **linkage**: that this machine's client was using
these particular **guard** relays at a particular time. Guards are deliberately
long-lived, kept for two to three months, and guard discovery is a real first
step in attacks on Tor users. Publishing that in a README, where it lives in git
history permanently, would be handing away exactly what `tort route` is gated
behind polkit to protect.

So the exit address, location and operator are placeholders, and relay nicknames
are `ExampleGuard`, `OtherMiddle` and so on. The exit address uses the RFC 5737
documentation range, like every other address in the documentation.

## What was deliberately kept

Country codes, and therefore the map. A guard being "in Germany" is not
identifying — Germany hosts hundreds of relays — and the country codes are what
make the map legible: without them the paths would have nowhere to run between.
Keeping them is what leaves the screenshot worth including.

## Regenerating

Take a screenshot of the running application, then redact the relay details
before committing it. A blurred region is not a safe redaction for text; replace
the values outright.
