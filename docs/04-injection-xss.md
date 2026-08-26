# 4. Injection & XSS

## XSS / SSTI Quick Probes

Standard breakout characters and math-evaluation probes to throw at every reflected parameter:

```
<> / '" & {7*7} / {{7*7}}
```

A reflected/evaluated `49` confirms server-side template injection; broken markup or script execution confirms XSS. See [Recon Stages 13, 15, and 18](01-recon-and-scoping.md#stage-13--xss-reflection-testing-active) for the full detection → confirmation pipeline (marker-based reflection testing, multi-engine SSTI probing, and headless-browser execution confirmation).

## SQL Injection

- **Logical-operation confirmation:** one of the most reliable ways to confirm SQLi is to make the query perform a logical operation and check the expected result. Example: if `?username=Ash` returns the same content as `?username=Ash'+AND+1='1`, while `?username=Ash'` alone breaks the page — you've found a SQL injection.
- **Characters that break the query:** `' " `  --  -- -  #  )  (`

See [Recon Stage 14](01-recon-and-scoping.md#stage-14--sql-injection-error-based-then-boolean-based-active) for the full error-based → boolean-based detection methodology, including response-length heuristics for blind cases.
