# imas — Infrastructure Management At Scale

**imas** is a SaaS-based machine manager: it executes commands and applies
configuration automation across virtual machines and bare-metal hosts, on
multiple clouds and on-premise. It began as a fork of
[gogrlx/grlx](https://github.com/gogrlx/grlx) (a Go/NATS fleet configuration
tool) and has since diverged into its own project, renamed **imas**.

A managed host is called a **sprout**. Sprouts connect over NATS to
**farmer**, the core service, which dispatches **recipes** — YAML documents
describing the desired state of a sprout — and **cooks** them: applies each
step (an **ingredient**) and reports whether it changed anything.

```yaml
# a recipe: a list of steps, each naming an ingredient and a method
webserver-running:
  service.running:
    - name: nginx

nginx-installed:
  pkg.installed:
    - name: nginx
```

This site covers:

- **[Installation](./installation.md)** — deploying farmer, the SaaS API,
  and enrolling sprouts.
- **[Ingredient reference](./ingredients/index.md)** — every ingredient a
  recipe can use: its methods and their parameters, generated directly from
  `internal/ingredients/` so it never drifts from the code.

For the platform's internal design (multi-tenancy, the SaaS API, signing and
key rotation, sprout orchestration), see
[`docs/design/`](https://github.com/yogzblr/imas/tree/main/docs/design) in
the repository — those documents explain *why* the platform is built the way
it is; this site documents *how to use it*.
