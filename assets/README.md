# Bundled map data

`world.json` contains simplified country outlines and label points derived from
[Natural Earth](https://www.naturalearthdata.com/) 110m Admin 0 – Countries.

Natural Earth is in the **public domain**; no permission is needed to use it,
and attribution is a courtesy rather than a requirement.

## What was done to it

- Coordinates rounded to one decimal place, roughly 11 km. The map is a few
  hundred pixels across, where that is well under one pixel.
- Consecutive duplicate points dropped, and rings of fewer than four points
  removed — islands that would not survive rounding anyway.
- `LABEL_X` / `LABEL_Y` kept as each country's location, keyed by ISO 3166-1
  alpha-2.

That takes 839 KB of GeoJSON to 134 KB.

Label points are used rather than computed centroids because for awkward shapes
— Norway, Chile, Indonesia — a centroid can land in the sea or in a neighbouring
country, while the label point is where a cartographer would write the name.

## Supplementary entries

Natural Earth's 110m set omits very small states, several of which host Tor
relays: Singapore, Hong Kong, Seychelles, Malta and others were added by hand
from their published coordinates. A relay in a country the map cannot place is
skipped rather than guessed at — a line to the wrong continent would be worse
than a gap.

## Regenerating

The data is checked in deliberately. Relay locations must never be looked up
over the network: asking a third party to place your guard, middle and exit
would disclose your whole path, which is far worse than the exit-only lookup
tort makes on purpose. Bundling is what keeps circuit inspection local.
