use std::{collections::BTreeMap, convert::Infallible};

use warp::{filters::BoxedFilter, Filter, Rejection};

use crate::handlers::AppContext;

pub fn make_path_filter(path: impl AsRef<str>) -> BoxedFilter<()> {
    let path = path.as_ref().trim_start_matches('/').to_string();
    if path.is_empty() {
        warp::path::end().boxed()
    } else {
        warp::path(path).and(warp::path::end()).boxed()
    }
}

pub fn with_context(ctx: AppContext) -> impl Filter<Extract = (AppContext,), Error = Infallible> + Clone {
    warp::any().map(move || ctx.clone())
}

pub fn get() -> impl Filter<Extract = (crate::JsonValue, ), Error = Rejection> + Clone {
    warp::get()
        // Put GET params into a BTreeMap so they become sorted
        .and(warp::query::<BTreeMap<String, String>>())
        .map(|params| crate::json!(params))
}

pub fn post() -> impl Filter<Extract = (crate::JsonValue, ), Error = Rejection> + Clone {
    warp::post()
        .and(warp::body::json::<crate::JsonValue>())
}
