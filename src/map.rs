//! World map rendering for circuit paths.
//!
//! Geometry comes from Natural Earth's 110m country dataset, which is in the
//! public domain, simplified to roughly 11 km precision and bundled with the
//! binary. Bundling matters: relay locations must never be looked up over the
//! network, because asking a third party to place your guard, middle and exit
//! would hand it your whole path — far worse than the exit-only lookup tort
//! already makes deliberately.
//!
//! Countries are placed at their label point rather than a computed centroid.
//! For awkward shapes — Norway, Chile, Indonesia — a centroid can fall in the
//! sea or in another country, while the label point is where a cartographer
//! would write the name.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Simplified country outlines and label points.
#[derive(Deserialize)]
pub struct World {
    /// Closed rings of [longitude, latitude] pairs.
    pub rings: Vec<Vec<[f64; 2]>>,
    /// ISO 3166-1 alpha-2 to [longitude, latitude].
    pub centroids: HashMap<String, [f64; 2]>,
}

static WORLD: LazyLock<World> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../assets/world.json"))
        .expect("bundled world.json is generated at build time and must parse")
});

pub fn world() -> &'static World {
    &WORLD
}

impl World {
    /// Where to draw a country, if we know it.
    pub fn locate(&self, country_code: &str) -> Option<[f64; 2]> {
        self.centroids.get(&country_code.to_uppercase()).copied()
    }
}

/// Maps longitude and latitude onto widget coordinates.
///
/// Equirectangular: longitude and latitude scale linearly. It distorts area
/// badly towards the poles, which would matter for a map that is about
/// territory. This one is about *which cities a path passes through*, and a
/// projection whose inverse is one subtraction keeps hit-testing and redrawing
/// trivial.
#[derive(Clone, Copy)]
pub struct Projection {
    pub x0: f64,
    pub y0: f64,
    pub scale_x: f64,
    pub scale_y: f64,
}

impl Projection {
    /// Fit the whole world into `width` x `height`, preserving aspect ratio and
    /// centring the result.
    pub fn fit(width: f64, height: f64) -> Self {
        // The world is 360 degrees wide and 180 tall, so a 2:1 box fits exactly.
        let scale = (width / 360.0).min(height / 180.0);
        Self {
            x0: (width - 360.0 * scale) / 2.0,
            y0: (height - 180.0 * scale) / 2.0,
            scale_x: scale,
            scale_y: scale,
        }
    }

    pub fn project(&self, lon: f64, lat: f64) -> (f64, f64) {
        (
            self.x0 + (lon + 180.0) * self.scale_x,
            // Latitude increases northwards, widget y increases downwards.
            self.y0 + (90.0 - lat) * self.scale_y,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_world_parses_and_has_geometry() {
        let w = world();
        assert!(w.rings.len() > 100, "expected country outlines");
        assert!(w.centroids.len() > 150, "expected most countries to be placed");
    }

    /// Countries that host Tor relays must be placeable, including the small
    /// states Natural Earth's 110m set omits.
    #[test]
    fn relay_hosting_countries_are_placeable() {
        let w = world();
        for code in ["US", "DE", "NL", "FR", "GB", "SE", "CH", "RO", "IS", "SC", "SG", "MT", "HK"] {
            assert!(w.locate(code).is_some(), "{code} should have a location");
        }
    }

    #[test]
    fn country_lookup_ignores_case() {
        assert_eq!(world().locate("de"), world().locate("DE"));
    }

    #[test]
    fn projection_places_the_corners_and_centre() {
        let p = Projection::fit(720.0, 360.0);
        let (x, y) = p.project(-180.0, 90.0);
        assert!(x.abs() < 0.01 && y.abs() < 0.01, "north-west corner is the origin");

        let (x, y) = p.project(0.0, 0.0);
        assert!((x - 360.0).abs() < 0.01 && (y - 180.0).abs() < 0.01, "null island is centred");
    }

    /// A non-2:1 widget must letterbox rather than stretch the world.
    #[test]
    fn projection_preserves_aspect_ratio() {
        let p = Projection::fit(1000.0, 300.0);
        assert!((p.scale_x - p.scale_y).abs() < f64::EPSILON);
        assert!(p.x0 > 0.0, "wide widget should pad horizontally");
    }
}
