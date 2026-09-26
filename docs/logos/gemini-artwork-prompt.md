# Gemini prompt — imas brand artwork

Use with Gemini's image generation (Gemini 3 Pro Image / "Nano Banana Pro").
Run the primary prompt first, then the two follow-ups for variants.

## Primary prompt

```
Design a modern, minimal logo mark for a developer tool called "imas"
(pronounced "eye-mas", short for Infrastructure Management At Scale — a
Go-based fleet/infrastructure automation platform, in the same category as
Salt, Ansible, or Terraform).

Style: flat vector, geometric, single memorable icon that works as a small
app icon/favicon as well as a large hero graphic. No gradients, no
photorealism, no drop shadows, no mockup devices, no text baked into the
icon itself.

Concept direction: something that reads as "many machines, one control
point" — e.g. a hub-and-spoke node graph, a small constellation of
connected squares/circles converging on a central node, or a stylized
network/root-system motif. Avoid anything resembling an existing brand
(no leaf/garlic references, no Kubernetes wheel, no Terraform "T").

Color: a single confident accent color (deep indigo, teal, or amber) on a
transparent or plain white background. Provide a light-mode and dark-mode
friendly version (i.e. the mark should still read clearly if placed on a
near-black background).

Output: the icon centered, plenty of even padding, square 1:1 canvas,
crisp clean edges suitable for vector tracing.
```

## Follow-up: wordmark lockup

```
Using the same icon and color from the previous image, create a horizontal
lockup: the icon on the left, followed by the wordmark "imas" in a clean
geometric sans-serif (like Inter, Manrope, or IBM Plex Sans), lowercase,
medium weight, tight letter-spacing. Transparent background. This is for a
README header and a CLI --help banner, so keep it legible at small sizes.
```

## Follow-up: README hero banner

```
Using the same icon and color palette, create a wide (3:1) banner
illustration for a GitHub README header: the imas mark on the left third,
and on the right two-thirds a simple flat-vector illustration of small
uniform server/node icons arranged in a loose grid, each connected back to
the mark by thin lines, suggesting fleet management at scale. Keep it flat
and minimal — no realistic hardware, no clutter, generous negative space.
```

## Notes for whoever runs this

- Ask for a few variations of the primary prompt and pick the cleanest
  mark before generating the lockup/banner from it, so all three stay
  consistent.
- Once you have a mark you like, get it re-exported as clean SVG (Gemini's
  raster output will need vector tracing — Illustrator's Image Trace or an
  online PNG-to-SVG tool works for a flat geometric mark like this).
- Replace `docs/logos/grlx.jpg` and `docs/diagrams/grlx-arch-light.png`
  with the new artwork once it exists, and re-add the logo to the top of
  README.md (removed during the grlx→imas rebrand since the old artwork
  was still literally the grlx logo).
