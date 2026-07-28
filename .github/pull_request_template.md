## Technical summary

Describe the problem, implementation, and observable behavior.

## Affected surface

- [ ] Portable core
- [ ] User-mode collector
- [ ] Kernel driver
- [ ] Driver protocol
- [ ] Event schema
- [ ] Build or CI
- [ ] Technical documentation

## Contract and security review

- [ ] No public interface or protocol change
- [ ] Interface or protocol changes are documented and versioned
- [ ] The telemetry-only boundary in `SECURITY.md` is preserved
- [ ] Kernel callback IRQL, lifetime, and unload behavior were reviewed
- [ ] New input lengths, counts, offsets, and integer conversions are bounded
- [ ] No credentials, signing keys, dumps, or sensitive logs are included

Delete checklist entries that cannot apply and explain any remaining unchecked
item.

## Validation

List the exact build, test, analysis, and runtime commands executed, including
architecture and relevant Windows SDK/WDK versions.

```text
command:
result:
```

## Related issue

Closes #
