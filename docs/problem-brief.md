# Problem Brief

## Chosen issue

The issue this repo targets is:

**software supply-chain compromise through CI/CD workflows, secret exfiltration, and package publishing abuse**

This was selected because it is both:

- highly time-sensitive in late April 2026
- concrete enough to support a useful open-source defense repo

## Why this was chosen

### 1. GitHub said the pattern is active now

GitHub wrote on **April 1, 2026** that recent open-source supply-chain attacks are focusing on **exfiltrating secrets** and that these attacks often start by compromising **GitHub Actions workflows**.

Source:
- [Securing the open source supply chain across GitHub](https://github.blog/security/supply-chain-security/securing-the-open-source-supply-chain-across-github/)

### 2. GitHub’s 2026 roadmap centers this exact problem

GitHub’s **March 26, 2026** Actions security roadmap says attackers are targeting **CI/CD automation itself**, and highlights:

- untrusted code execution
- malicious workflows without observability
- compromised dependencies spreading broadly
- over-permissioned credentials being exfiltrated

Source:
- [What’s coming to our GitHub Actions 2026 security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/)

### 3. Registry operators are tightening trusted publishing

npm announced on **April 6, 2026** that trusted publishing now supports CircleCI, extending OIDC-based publishing and reducing the need for stored tokens.

Source:
- [npm trusted publishing now supports CircleCI](https://github.blog/changelog/2026-04-06-npm-trusted-publishing-now-supports-circleci/)

PyPI’s **April 16, 2026** security audit also included OIDC-related findings and organizational-control issues.

Source:
- [PyPI has completed its second audit](https://blog.pypi.org/posts/2026-04-16-pypi-completes-second-audit/)

### 4. Recent incidents reinforce that this is not hypothetical

On **April 23, 2026**, Socket reported that Bitwarden CLI was compromised after attackers abused a GitHub Action in its CI/CD pipeline.

Source:
- [Bitwarden CLI Compromised in Ongoing Checkmarx Supply Chain Campaign](https://socket.dev/blog/bitwarden-cli-compromised)

On **April 30, 2026**, Snyk reported the malicious `lightning` PyPI releases that carried a Bun-based credential stealer.

Source:
- [Lightning PyPI Compromise: A Bun-Based Credential Stealer in Python](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/)

## Product thesis

Teams do not just need “another SBOM” or “another vulnerability list.”

They need a repo-native tool that tells them:

- which workflows are exploitable
- which publishing lanes still rely on long-lived secrets
- which jobs run with more privilege than necessary
- which changes should be fixed first

That is the job of `supply-chain-firebreak`.
