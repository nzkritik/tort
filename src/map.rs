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

/// A longitude/latitude window to display.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    pub lon_min: f64,
    pub lon_max: f64,
    pub lat_min: f64,
    pub lat_max: f64,
}

impl Bounds {
    pub fn world() -> Self {
        Self { lon_min: -180.0, lon_max: 180.0, lat_min: -85.0, lat_max: 85.0 }
    }

    /// The smallest window containing every point.
    ///
    /// Longitude is measured twice - once as given, once with negative values
    /// shifted past 180 - and whichever yields the narrower span wins. Without
    /// that, a circuit from Japan to the United States spans nearly the whole
    /// globe the short way round the wrong side, and the map zooms out to
    /// almost nothing rather than framing the Pacific.
    pub fn around(points: &[[f64; 2]]) -> Option<Self> {
        if points.is_empty() {
            return None;
        }

        let lat_min = points.iter().map(|p| p[1]).fold(f64::MAX, f64::min);
        let lat_max = points.iter().map(|p| p[1]).fold(f64::MIN, f64::max);

        let plain: Vec<f64> = points.iter().map(|p| p[0]).collect();
        let shifted: Vec<f64> = plain.iter().map(|l| if *l < 0.0 { l + 360.0 } else { *l }).collect();

        let span = |v: &[f64]| {
            let lo = v.iter().copied().fold(f64::MAX, f64::min);
            let hi = v.iter().copied().fold(f64::MIN, f64::max);
            (lo, hi, hi - lo)
        };

        let (a_lo, a_hi, a_span) = span(&plain);
        let (b_lo, b_hi, b_span) = span(&shifted);
        let (lon_min, lon_max) = if b_span < a_span { (b_lo, b_hi) } else { (a_lo, a_hi) };

        Some(Self { lon_min, lon_max, lat_min, lat_max })
    }

    /// Grow the window so the outermost points are not against the edge.
    ///
    /// A minimum span is enforced as well as a proportional margin: three relays
    /// in one country would otherwise produce a near-zero span and a zoom level
    /// showing a few streets.
    pub fn padded(self, fraction: f64, min_span: f64) -> Self {
        let (clon, clat) = self.centre();
        let lon_span = ((self.lon_max - self.lon_min) * (1.0 + fraction)).max(min_span);
        let lat_span = ((self.lat_max - self.lat_min) * (1.0 + fraction)).max(min_span / 2.0);

        Self {
            lon_min: clon - lon_span / 2.0,
            lon_max: clon + lon_span / 2.0,
            lat_min: clat - lat_span / 2.0,
            lat_max: clat + lat_span / 2.0,
        }
    }

    pub fn centre(&self) -> (f64, f64) {
        ((self.lon_min + self.lon_max) / 2.0, (self.lat_min + self.lat_max) / 2.0)
    }
}

/// Maps longitude and latitude onto widget coordinates.
///
/// Equirectangular: longitude and latitude scale linearly. It distorts area
/// badly towards the poles, which would matter for a map that is about
/// territory. This one is about *which cities a path passes through*, and a
/// projection this simple keeps redrawing and zooming trivial.
#[derive(Clone, Copy)]
pub struct Projection {
    centre_lon: f64,
    centre_lat: f64,
    scale: f64,
    width: f64,
    height: f64,
}

impl Projection {
    /// Fit `bounds` into the widget, magnified by `zoom`.
    ///
    /// Aspect ratio is preserved: the tighter of the two axes decides the scale,
    /// so the window letterboxes rather than stretching the world.
    pub fn new(bounds: &Bounds, width: f64, height: f64, zoom: f64) -> Self {
        let lon_span = (bounds.lon_max - bounds.lon_min).max(1.0);
        let lat_span = (bounds.lat_max - bounds.lat_min).max(1.0);
        let scale = (width / lon_span).min(height / lat_span) * zoom;
        let (centre_lon, centre_lat) = bounds.centre();

        Self { centre_lon, centre_lat, scale, width, height }
    }

    pub fn project(&self, lon: f64, lat: f64) -> (f64, f64) {
        (
            self.width / 2.0 + self.wrap(lon) * self.scale,
            // Latitude increases northwards, widget y increases downwards.
            self.height / 2.0 + (self.centre_lat - lat) * self.scale,
        )
    }

    /// Longitude relative to the centre, taken the short way round.
    ///
    /// Without this a view centred near the antimeridian puts points a few
    /// degrees apart on opposite sides of the widget.
    pub fn wrap(&self, lon: f64) -> f64 {
        let mut delta = lon - self.centre_lon;
        while delta > 180.0 {
            delta -= 360.0;
        }
        while delta < -180.0 {
            delta += 360.0;
        }
        delta
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
    fn projection_centres_the_bounds() {
        let p = Projection::new(&Bounds::world(), 720.0, 360.0, 1.0);
        let (x, y) = p.project(0.0, 0.0);
        assert!((x - 360.0).abs() < 0.01 && (y - 180.0).abs() < 0.01, "null island is centred");
    }

    /// A non-square view must letterbox rather than stretch the world.
    #[test]
    fn projection_preserves_aspect_ratio() {
        let p = Projection::new(&Bounds::world(), 1000.0, 300.0, 1.0);
        let (x1, _) = p.project(10.0, 0.0);
        let (_, y1) = p.project(0.0, 10.0);
        let (x0, y0) = p.project(0.0, 0.0);
        assert!(((x1 - x0) - (y0 - y1)).abs() < 0.01, "degrees must scale equally on both axes");
    }

    #[test]
    fn zoom_magnifies_about_the_centre() {
        let b = Bounds::world();
        let near = Projection::new(&b, 800.0, 400.0, 2.0);
        let far = Projection::new(&b, 800.0, 400.0, 1.0);

        let (cx, _) = near.project(0.0, 0.0);
        assert!((cx - 400.0).abs() < 0.01, "the centre stays put when zooming");

        let spread = |p: &Projection| p.project(40.0, 0.0).0 - p.project(0.0, 0.0).0;
        assert!(spread(&near) > spread(&far) * 1.9, "zooming in must spread points apart");
    }

    /// A circuit spanning the Pacific must frame the Pacific, not the globe.
    #[test]
    fn bounds_take_the_short_way_across_the_antimeridian() {
        // Tokyo and San Francisco: 20 degrees apart the short way, 340 the long.
        let b = Bounds::around(&[[139.7, 35.7], [-122.4, 37.8]]).unwrap();
        assert!(
            b.lon_max - b.lon_min < 130.0,
            "expected the Pacific framing, got a span of {}",
            b.lon_max - b.lon_min
        );
    }

    #[test]
    fn bounds_of_nearby_points_are_widened_to_something_usable() {
        // Three relays in one country would otherwise zoom to a few streets.
        let b = Bounds::around(&[[9.6, 50.9], [9.7, 51.0]]).unwrap().padded(0.25, 30.0);
        assert!(b.lon_max - b.lon_min >= 30.0);
    }

    #[test]
    fn wrap_takes_the_short_way() {
        let p = Projection::new(
            &Bounds { lon_min: 170.0, lon_max: 190.0, lat_min: -10.0, lat_max: 10.0 },
            400.0, 200.0, 1.0,
        );
        // 179 and -179 are two degrees apart, not 358.
        assert!((p.wrap(179.0) - p.wrap(-179.0)).abs() < 3.0);
    }
}
