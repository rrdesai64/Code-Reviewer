# Injection And Execution Guidance

## CWE-78 OS Command Injection Remediation
Use argument-array execution APIs instead of shell strings. Validate user-selectable command names with explicit allowlists, reject shell metacharacters when commands are unavoidable, and keep environment variables separate from user input. Prefer `subprocess.run([...], check=True)` in Python and `execFile` or `spawn` with argument arrays in Node.js. Add regression tests that pass hostile input containing separators such as `;`, `&&`, pipes, and command substitutions.

## CWE-89 SQL Injection Remediation
Use parameterized queries or ORM query builders that bind values separately from SQL text. Never concatenate request input into SQL strings. Validate identifiers such as table or column names against allowlists because bind parameters usually protect values, not SQL structure. Add tests for quote characters, stacked statements, tautologies, and database-specific comment syntax.

## CWE-79 Cross-Site Scripting Remediation
Render user-controlled text through framework escaping defaults. Avoid direct `innerHTML`, template bypasses, unsafe markdown rendering, and string-built script blocks. If rich text is required, sanitize with a maintained allowlist sanitizer and deploy a Content Security Policy that limits script sources. Verify both stored and reflected rendering paths.

## CWE-94 Dynamic Code Execution Remediation
Replace `eval`, `exec`, dynamic `Function`, or runtime code compilation with parsers, schema validation, command dispatch tables, or safe expression evaluators. Treat configuration and workflow definitions as data. Add tests that prove untrusted strings are not evaluated as code.
