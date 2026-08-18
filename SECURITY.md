# Security Policy


Talmi is a short-lived token service. Its whole job is to decide who may mint which
downstream tokens, so security reports get priority.


## Supported versions


Talmi has not reached a stable 1.0 release yet. Only the latest tagged release and the
`main` branch receive security fixes. If you run an older tag, upgrade before reporting.


## Reporting a vulnerability


Please report privately. Do not open a public issue, PR, or discussion for anything that could
be exploited.

Use GitHub's private vulnerability reporting: open the
[Security tab](https://github.com/darmiel/talmi/security/advisories) and choose "Report a
vulnerability". This creates a private advisory only you and the maintainers can see.

If you cannot use GitHub advisories, please reach the maintainer through the contact listed on
the [darmiel GitHub profile](https://github.com/darmiel).

Please include what you need for us to reproduce it:


- affected version or commit;
- the config surface involved (issuer, realm, rule, config source, provider);
- steps to reproduce, plus a proof of concept if you have one;
- the impact you think it has (who gets to mint what, or what leaks).


Never include real secrets in a report. Reference the scheme or variable name, the same
way Talmi's own error messages do.


## What counts as a vulnerability


The authorization decision is the core invariant. Anything that lets a caller mint a token
it should not, escalate scope past a realm's capability ceiling, spoof a verified identity,
or bypass default-deny is in scope. So is leaking secret values into logs or responses,
predicting server-generated lease or audit IDs, or the config-source trust boundary sending
host secrets somewhere it should not.


## Disclosure


We aim to acknowledge a report within a few days and will keep you updated as we confirm
and fix it. Once a fix ships, we will publish an advisory and credit you unless you would
rather stay anonymous.
